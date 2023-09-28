import asyncio
import logging
import typing
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    AsyncIterable,
    Coroutine,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    Union,
)

from aleph_message import MessagesResponse
from aleph_message.models import AlephMessage, Chain, ItemHash, MessageType, PostMessage
from aleph_message.models.execution.base import Encoding
from aleph_message.status import MessageStatus

from .base import BaseAlephClient, BaseAuthenticatedAlephClient
from .client import AuthenticatedAlephClient
from .conf import settings
from .exceptions import MessageNotFoundError
from .models.db.common import db
from .models.db.message import MessageDBModel
from .models.db.post import PostDBModel
from .models.message import MessageFilter, message_to_model, model_to_message
from .models.post import Post, PostFilter, PostsResponse
from .types import GenericMessage, StorageEnum


class MessageCache(BaseAlephClient):
    """
    A wrapper around a sqlite3 database for caching AlephMessage objects.

    It can be used independently of a DomainNode to implement any kind of caching strategy.
    """

    _instance_count = 0  # Class-level counter for active instances
    missing_posts: Dict[ItemHash, PostMessage] = {}
    """A dict of all posts by item_hash and their amend messages that are missing from the cache."""

    def __init__(self):
        if db.is_closed():
            db.connect()
            if not MessageDBModel.table_exists():
                db.create_tables([MessageDBModel])
            if not PostDBModel.table_exists():
                db.create_tables([PostDBModel])

        MessageCache._instance_count += 1

    def __del__(self):
        MessageCache._instance_count -= 1

        if MessageCache._instance_count == 0:
            db.close()

    def __getitem__(self, item_hash: Union[ItemHash, str]) -> Optional[AlephMessage]:
        try:
            item = MessageDBModel.get(MessageDBModel.item_hash == str(item_hash))
        except MessageDBModel.DoesNotExist:
            return None
        return model_to_message(item)

    def __delitem__(self, item_hash: Union[ItemHash, str]):
        MessageDBModel.delete().where(
            MessageDBModel.item_hash == str(item_hash)
        ).execute()

    def __contains__(self, item_hash: Union[ItemHash, str]) -> bool:
        return (
            MessageDBModel.select()
            .where(MessageDBModel.item_hash == str(item_hash))
            .exists()
        )

    def __len__(self):
        return MessageDBModel.select().count()

    def __iter__(self) -> Iterator[AlephMessage]:
        """
        Iterate over all messages in the cache, the latest first.
        """
        for item in iter(MessageDBModel.select().order_by(-MessageDBModel.time)):
            yield model_to_message(item)

    def __repr__(self) -> str:
        return f"<MessageCache: {db}>"

    def __str__(self) -> str:
        return repr(self)

    def add(self, messages: Union[AlephMessage, Iterable[AlephMessage]]):
        """
        Add a message or a list of messages to the cache. If the message is a post, it will also be added to the
        PostDBModel. Any subsequent amend messages will be used to update the original post in the PostDBModel.
        """
        if isinstance(messages, typing.get_args(AlephMessage)):
            messages = [messages]

        messages = list(messages)

        message_data = (message_to_model(message) for message in messages)
        MessageDBModel.insert_many(message_data).on_conflict_replace().execute()

        # Add posts and their amends to the PostDBModel
        post_data = []
        amend_messages = []
        for message in messages:
            if message.type != MessageType.post.value:
                continue
            if message.content.type == "amend":
                amend_messages.append(message)
                continue
            post = Post.from_message(message).dict()
            post["chain"] = message.chain.value
            post["tags"] = message.content.content.get("tags", None)
            post_data.append(post)
            # Check if we can now add any amend messages that had missing refs
            if message.item_hash in self.missing_posts:
                amend_messages += self.missing_posts.pop(message.item_hash)

        PostDBModel.insert_many(post_data).on_conflict_replace().execute()

        # Handle amends in second step to avoid missing original posts
        for message in amend_messages:
            logging.debug(f"Adding amend {message.item_hash} to cache")
            # Find the original post and update it
            original_post = PostDBModel.get(
                PostDBModel.item_hash == message.content.ref
            )
            if not original_post:
                latest_amend = self.missing_posts.get(ItemHash(message.content.ref))
                if latest_amend and message.time < latest_amend.time:
                    self.missing_posts[ItemHash(message.content.ref)] = message
                continue
            if datetime.fromtimestamp(message.time) < original_post.last_updated:
                continue
            original_post.content = message.content.content
            original_post.original_item_hash = message.content.ref
            original_post.original_type = message.content.type
            original_post.address = message.sender
            original_post.channel = message.channel
            original_post.last_updated = datetime.fromtimestamp(message.time)
            original_post.save()

    def get(
        self, item_hashes: Union[Union[ItemHash, str], Iterable[Union[ItemHash, str]]]
    ) -> List[AlephMessage]:
        """
        Get many messages from the cache by their item hash.
        """
        if not isinstance(item_hashes, list):
            item_hashes = [item_hashes]
        item_hashes = [str(item_hash) for item_hash in item_hashes]
        items = (
            MessageDBModel.select()
            .where(MessageDBModel.item_hash.in_(item_hashes))
            .execute()
        )
        return [model_to_message(item) for item in items]

    def listen_to(self, message_stream: AsyncIterable[AlephMessage]) -> Coroutine:
        """
        Listen to a stream of messages and add them to the cache.
        """

        async def _listen():
            async for message in message_stream:
                self.add(message)
                logging.info(f"Added message {message.item_hash} to cache")

        return _listen()

    async def fetch_aggregate(
        self, address: str, key: str, limit: int = 100
    ) -> Dict[str, Dict]:
        item = (
            MessageDBModel.select()
            .where(MessageDBModel.type == MessageType.aggregate.value)
            .where(MessageDBModel.sender == address)
            .where(MessageDBModel.key == key)
            .order_by(MessageDBModel.time.desc())
            .first()
        )
        return item.content["content"]

    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None, limit: int = 100
    ) -> Dict[str, Dict]:
        query = (
            MessageDBModel.select()
            .where(MessageDBModel.type == MessageType.aggregate.value)
            .where(MessageDBModel.sender == address)
            .order_by(MessageDBModel.time.desc())
        )
        if keys:
            query = query.where(MessageDBModel.key.in_(keys))
        query = query.limit(limit)
        return {item.key: item.content["content"] for item in list(query)}

    async def get_posts(
        self,
        pagination: int = 200,
        page: int = 1,
        post_filter: Optional[PostFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> PostsResponse:
        if not post_filter:
            post_filter = PostFilter()
        query = post_filter.as_db_query()

        query = query.paginate(page, pagination)

        posts = [Post.from_orm(item) for item in list(query)]

        return PostsResponse(
            posts=posts,
            pagination_page=page,
            pagination_per_page=pagination,
            pagination_total=query.count(),
            pagination_item="posts",
        )

    async def download_file(self, file_hash: str) -> bytes:
        raise NotImplementedError

    async def get_messages(
        self,
        pagination: int = 200,
        page: int = 1,
        message_filter: Optional[MessageFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> MessagesResponse:
        """
        Get many messages from the cache.
        """
        if not message_filter:
            message_filter = MessageFilter()

        query = message_filter.as_db_query()

        query = query.paginate(page, pagination)

        messages = [model_to_message(item) for item in list(query)]

        return MessagesResponse(
            messages=messages,
            pagination_page=page,
            pagination_per_page=pagination,
            pagination_total=query.count(),
            pagination_item="messages",
        )

    async def get_message(
        self,
        item_hash: str,
        message_type: Optional[Type[GenericMessage]] = None,
        channel: Optional[str] = None,
    ) -> GenericMessage:
        """
        Get a single message from the cache.
        """
        query = MessageDBModel.select().where(MessageDBModel.item_hash == item_hash)

        if message_type:
            query = query.where(MessageDBModel.type == message_type.value)
        if channel:
            query = query.where(MessageDBModel.channel == channel)

        item = query.first()

        if item:
            return model_to_message(item)

        raise MessageNotFoundError(f"No such hash {item_hash}")

    async def watch_messages(
        self,
        message_filter: Optional[MessageFilter] = None,
    ) -> AsyncIterable[AlephMessage]:
        """
        Watch messages from the cache.
        """
        if not message_filter:
            message_filter = MessageFilter()

        query = message_filter.as_db_query()

        async for item in query:
            yield model_to_message(item)


class DomainNode(MessageCache, BaseAuthenticatedAlephClient):
    """
    A Domain Node is a queryable proxy for Aleph Messages that are stored in a database cache and/or in the Aleph
    network.

    It synchronizes with the network on a subset of the messages (the "domain") by listening to the network and storing the
    messages in the cache. The user may define the domain by specifying a channels, tags, senders, chains and/or
    message types.

    By default, the domain is defined by the user's own address and used chain, meaning that the DomainNode will only
    store and create messages that are sent by the user.
    """

    session: AuthenticatedAlephClient
    message_filter: MessageFilter
    watch_task: Optional[asyncio.Task] = None

    def __init__(
        self,
        session: AuthenticatedAlephClient,
        message_filter: Optional[MessageFilter] = None,
    ):
        super().__init__()
        self.session = session
        if not message_filter:
            message_filter = MessageFilter()
        message_filter.addresses = list(
            set(
                (
                    list(message_filter.addresses) + [session.account.get_address()]
                    if message_filter.addresses
                    else [session.account.get_address()]
                )
            )
        )
        message_filter.chains = list(
            set(
                (
                    list(message_filter.chains) + [Chain(session.account.CHAIN)]
                    if message_filter.chains
                    else [session.account.CHAIN]
                )
            )
        )
        self.message_filter = message_filter

        # start listening to the network and storing messages in the cache
        self.watch_task = asyncio.get_event_loop().create_task(
            self.listen_to(
                self.session.watch_messages(
                    message_filter=self.message_filter,
                )
            )
        )

        # synchronize with past messages
        asyncio.get_event_loop().run_until_complete(
            self.synchronize(
                message_filter=self.message_filter,
            )
        )

    def __del__(self):
        if self.watch_task:
            self.watch_task.cancel()

    def __exit__(self, exc_type, exc_val, exc_tb):
        close_fut = self.session.__aexit__(exc_type, exc_val, exc_tb)
        try:
            loop = asyncio.get_running_loop()
            loop.run_until_complete(close_fut)
        except RuntimeError:
            asyncio.run(close_fut)

    async def __aenter__(self) -> "DomainNode":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.__aexit__(exc_type, exc_val, exc_tb)

    async def synchronize(
        self,
        message_filter: MessageFilter,
    ):
        """
        Synchronize with past messages.
        """
        chunk_size = 200
        messages = []
        async for message in self.session.get_messages_iterator(
            message_filter=message_filter
        ):
            messages.append(message)
            if len(messages) >= chunk_size:
                self.add(messages)
                messages = []
        if messages:
            self.add(messages)

    async def download_file(self, file_hash: str) -> bytes:
        """
        Opens a file that has been locally stored by its hash.
        """
        try:
            with open(self._file_path(file_hash), "rb") as f:
                return f.read()
        except FileNotFoundError:
            file = await self.session.download_file(file_hash)
            self._file_path(file_hash).parent.mkdir(parents=True, exist_ok=True)
            with open(self._file_path(file_hash), "wb") as f:
                f.write(file)
            return file

    @staticmethod
    def _file_path(file_hash: str) -> Path:
        return settings.CACHE_FILES_PATH / Path(file_hash)

    def check_validity(
        self,
        message_type: MessageType,
        address: Optional[str] = None,
        channel: Optional[str] = None,
        content: Optional[Dict] = None,
    ):
        if (
            self.message_filter.message_types
            and message_type not in self.message_filter.message_types
        ):
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to post messages."
            )
        if (
            address
            and self.message_filter.addresses
            and address not in self.message_filter.addresses
        ):
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to messages from address {address}."
            )
        if (
            channel
            and self.message_filter.channels
            and channel not in self.message_filter.channels
        ):
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to messages from channel {channel}."
            )
        if (
            content
            and self.message_filter.tags
            and not set(content.get("tags", [])).intersection(self.message_filter.tags)
        ):
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to any of these tags: {content.get('tags', [])}."
            )

    async def create_post(
        self,
        post_content: Any,
        post_type: str,
        ref: Optional[str] = None,
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        storage_engine: StorageEnum = StorageEnum.storage,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(MessageType.post, address, channel, post_content)
        resp, status = await self.session.create_post(
            post_content=post_content,
            post_type=post_type,
            ref=ref,
            address=address,
            channel=channel,
            inline=inline,
            storage_engine=storage_engine,
            sync=sync,
        )
        print(resp)
        # WARNING: this can cause inconsistencies if the message is dropped/rejected by the aleph node
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        return resp, status

    async def create_aggregate(
        self,
        key: str,
        content: Mapping[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(MessageType.aggregate, address, channel)
        resp, status = await self.session.create_aggregate(
            key=key,
            content=content,
            address=address,
            channel=channel,
            inline=inline,
            sync=sync,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        return resp, status

    async def create_store(
        self,
        address: Optional[str] = None,
        file_content: Optional[bytes] = None,
        file_path: Optional[Union[str, Path]] = None,
        file_hash: Optional[str] = None,
        guess_mime_type: bool = False,
        ref: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        extra_fields: Optional[dict] = None,
        channel: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(MessageType.store, address, channel, extra_fields)
        resp, status = await self.session.create_store(
            address=address,
            file_content=file_content,
            file_path=file_path,
            file_hash=file_hash,
            guess_mime_type=guess_mime_type,
            ref=ref,
            storage_engine=storage_engine,
            extra_fields=extra_fields,
            channel=channel,
            sync=sync,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        return resp, status

    async def create_program(
        self,
        program_ref: str,
        entrypoint: str,
        runtime: str,
        environment_variables: Optional[Mapping[str, str]] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
        memory: Optional[int] = None,
        vcpus: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        persistent: bool = False,
        encoding: Encoding = Encoding.zip,
        volumes: Optional[List[Mapping]] = None,
        subscriptions: Optional[List[Mapping]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(
            MessageType.program, address, channel, dict(metadata) if metadata else None
        )
        resp, status = await self.session.create_program(
            program_ref=program_ref,
            entrypoint=entrypoint,
            runtime=runtime,
            environment_variables=environment_variables,
            storage_engine=storage_engine,
            channel=channel,
            address=address,
            sync=sync,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            persistent=persistent,
            encoding=encoding,
            volumes=volumes,
            subscriptions=subscriptions,
            metadata=metadata,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        return resp, status

    async def forget(
        self,
        hashes: List[str],
        reason: Optional[str],
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(MessageType.forget, address, channel)
        resp, status = await self.session.forget(
            hashes=hashes,
            reason=reason,
            storage_engine=storage_engine,
            channel=channel,
            address=address,
            sync=sync,
        )
        del self[resp.item_hash]
        return resp, status

    async def submit(
        self,
        content: Dict[str, Any],
        message_type: MessageType,
        channel: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        allow_inlining: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        resp, status = await self.session.submit(
            content=content,
            message_type=message_type,
            channel=channel,
            storage_engine=storage_engine,
            allow_inlining=allow_inlining,
            sync=sync,
        )
        # WARNING: this can cause inconsistencies if the message is dropped/rejected by the aleph node
        if status in [MessageStatus.PROCESSED, MessageStatus.PENDING]:
            self.add(resp)
        return resp, status
