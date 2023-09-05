import asyncio
import json
import logging
import typing
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import (
    Any,
    AsyncIterable,
    Coroutine,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from aleph_message import MessagesResponse, parse_message
from aleph_message.models import (
    AlephMessage,
    Chain,
    ItemHash,
    MessageConfirmation,
    MessageType,
)
from aleph_message.models.execution.base import Encoding
from aleph_message.status import MessageStatus
from peewee import (
    BooleanField,
    CharField,
    FloatField,
    IntegerField,
    Model,
    SqliteDatabase,
)
from playhouse.shortcuts import model_to_dict
from playhouse.sqlite_ext import JSONField
from pydantic import BaseModel

from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.base import AlephClientBase, AuthenticatedAlephClientBase
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import MessageNotFoundError
from aleph.sdk.models import PostsResponse
from aleph.sdk.types import GenericMessage, StorageEnum

db = SqliteDatabase(settings.CACHE_DATABASE_PATH)
T = TypeVar("T", bound=BaseModel)


class JSONDictEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BaseModel):
            return obj.dict()
        return json.JSONEncoder.default(self, obj)


pydantic_json_dumps = partial(json.dumps, cls=JSONDictEncoder)


class PydanticField(JSONField, Generic[T]):
    """
    A field for storing pydantic model types as JSON in a database. Uses json for serialization.
    """

    type: T

    def __init__(self, *args, **kwargs):
        self.type = kwargs.pop("type")
        super().__init__(*args, **kwargs)

    def db_value(self, value: Optional[T]) -> Optional[str]:
        if value is None:
            return None
        return value.json()

    def python_value(self, value: Optional[str]) -> Optional[T]:
        if value is None:
            return None
        return self.type.parse_raw(value)


class MessageModel(Model):
    """
    A simple database model for storing AlephMessage objects.
    """

    item_hash = CharField(primary_key=True)
    chain = CharField(5)
    type = CharField(9)
    sender = CharField()
    channel = CharField(null=True)
    confirmations: PydanticField[MessageConfirmation] = PydanticField(
        type=MessageConfirmation, null=True
    )
    confirmed = BooleanField(null=True)
    signature = CharField(null=True)
    size = IntegerField(null=True)
    time = FloatField()
    item_type = CharField(7)
    item_content = CharField(null=True)
    hash_type = CharField(6, null=True)
    content = JSONField(json_dumps=pydantic_json_dumps)
    forgotten_by = CharField(null=True)
    tags = JSONField(json_dumps=pydantic_json_dumps, null=True)
    key = CharField(null=True)
    ref = CharField(null=True)
    content_type = CharField(null=True)

    class Meta:
        database = db


def message_to_model(message: AlephMessage) -> Dict:
    return {
        "item_hash": str(message.item_hash),
        "chain": message.chain,
        "type": message.type,
        "sender": message.sender,
        "channel": message.channel,
        "confirmations": message.confirmations[0] if message.confirmations else None,
        "confirmed": message.confirmed,
        "signature": message.signature,
        "size": message.size,
        "time": message.time,
        "item_type": message.item_type,
        "item_content": message.item_content,
        "hash_type": message.hash_type,
        "content": message.content,
        "forgotten_by": message.forgotten_by[0] if message.forgotten_by else None,
        "tags": message.content.content.get("tags", None)
        if hasattr(message.content, "content")
        else None,
        "key": message.content.key if hasattr(message.content, "key") else None,
        "ref": message.content.ref if hasattr(message.content, "ref") else None,
        "content_type": message.content.type
        if hasattr(message.content, "type")
        else None,
    }


def model_to_message(item: Any) -> AlephMessage:
    item.confirmations = [item.confirmations] if item.confirmations else []
    item.forgotten_by = [item.forgotten_by] if item.forgotten_by else None

    to_exclude = [
        MessageModel.tags,
        MessageModel.ref,
        MessageModel.key,
        MessageModel.content_type,
    ]

    item_dict = model_to_dict(item, exclude=to_exclude)
    return parse_message(item_dict)


def query_field(field_name, field_values: Iterable[str]):
    field = getattr(MessageModel, field_name)
    values = list(field_values)

    if len(values) == 1:
        return field == values[0]
    return field.in_(values)


def get_message_query(
    message_type: Optional[MessageType] = None,
    content_keys: Optional[Iterable[str]] = None,
    content_types: Optional[Iterable[str]] = None,
    refs: Optional[Iterable[str]] = None,
    addresses: Optional[Iterable[str]] = None,
    tags: Optional[Iterable[str]] = None,
    hashes: Optional[Iterable[str]] = None,
    channels: Optional[Iterable[str]] = None,
    chains: Optional[Iterable[str]] = None,
    start_date: Optional[Union[datetime, float]] = None,
    end_date: Optional[Union[datetime, float]] = None,
):
    query = MessageModel.select().order_by(MessageModel.time.desc())
    conditions = []
    if message_type:
        conditions.append(query_field("type", [message_type.value]))
    if content_keys:
        conditions.append(query_field("key", content_keys))
    if content_types:
        conditions.append(query_field("content_type", content_types))
    if refs:
        conditions.append(query_field("ref", refs))
    if addresses:
        conditions.append(query_field("sender", addresses))
    if tags:
        for tag in tags:
            conditions.append(MessageModel.tags.contains(tag))
    if hashes:
        conditions.append(query_field("item_hash", hashes))
    if channels:
        conditions.append(query_field("channel", channels))
    if chains:
        conditions.append(query_field("chain", chains))
    if start_date:
        conditions.append(MessageModel.time >= start_date)
    if end_date:
        conditions.append(MessageModel.time <= end_date)

    if conditions:
        query = query.where(*conditions)
    return query


class MessageCache(AlephClientBase):
    """
    A wrapper around a sqlite3 database for caching AlephMessage objects.

    It can be used independently of a DomainNode to implement any kind of caching strategy.
    """

    _instance_count = 0  # Class-level counter for active instances

    def __init__(self):
        if db.is_closed():
            db.connect()
            if not MessageModel.table_exists():
                db.create_tables([MessageModel])

        MessageCache._instance_count += 1

    def __del__(self):
        MessageCache._instance_count -= 1

        if MessageCache._instance_count == 0:
            db.close()

    def __getitem__(self, item_hash: Union[ItemHash, str]) -> Optional[AlephMessage]:
        try:
            item = MessageModel.get(MessageModel.item_hash == str(item_hash))
        except MessageModel.DoesNotExist:
            return None
        return model_to_message(item)

    def __delitem__(self, item_hash: Union[ItemHash, str]):
        MessageModel.delete().where(MessageModel.item_hash == str(item_hash)).execute()

    def __contains__(self, item_hash: Union[ItemHash, str]) -> bool:
        return (
            MessageModel.select()
            .where(MessageModel.item_hash == str(item_hash))
            .exists()
        )

    def __len__(self):
        return MessageModel.select().count()

    def __iter__(self) -> Iterator[AlephMessage]:
        """
        Iterate over all messages in the cache, the latest first.
        """
        for item in iter(MessageModel.select().order_by(-MessageModel.time)):
            yield model_to_message(item)

    def __repr__(self) -> str:
        return f"<MessageCache: {db}>"

    def __str__(self) -> str:
        return repr(self)

    @staticmethod
    def add(messages: Union[AlephMessage, Iterable[AlephMessage]]):
        if isinstance(messages, typing.get_args(AlephMessage)):
            messages = [messages]

        data_source = (message_to_model(message) for message in messages)
        MessageModel.insert_many(data_source).on_conflict_replace().execute()

    @staticmethod
    def get(
        item_hashes: Union[Union[ItemHash, str], Iterable[Union[ItemHash, str]]]
    ) -> List[AlephMessage]:
        """
        Get many messages from the cache by their item hash.
        """
        if not isinstance(item_hashes, list):
            item_hashes = [item_hashes]
        item_hashes = [str(item_hash) for item_hash in item_hashes]
        items = (
            MessageModel.select()
            .where(MessageModel.item_hash.in_(item_hashes))
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
                print(f"Added message {message.item_hash} to cache")

        return _listen()

    async def fetch_aggregate(
        self, address: str, key: str, limit: int = 100
    ) -> Dict[str, Dict]:
        item = (
            MessageModel.select()
            .where(MessageModel.type == MessageType.aggregate.value)
            .where(MessageModel.sender == address)
            .where(MessageModel.key == key)
            .order_by(MessageModel.time.desc())
            .first()
        )
        return item.content["content"]

    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None, limit: int = 100
    ) -> Dict[str, Dict]:
        query = (
            MessageModel.select()
            .where(MessageModel.type == MessageType.aggregate.value)
            .where(MessageModel.sender == address)
            .order_by(MessageModel.time.desc())
        )
        if keys:
            query = query.where(MessageModel.key.in_(keys))
        query = query.limit(limit)
        return {item.key: item.content["content"] for item in list(query)}

    async def get_posts(
        self,
        pagination: int = 200,
        page: int = 1,
        types: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ) -> PostsResponse:
        query = get_message_query(
            message_type=MessageType.post,
            content_types=types,
            refs=refs,
            addresses=addresses,
            tags=tags,
            hashes=hashes,
            channels=channels,
            chains=chains,
            start_date=start_date,
            end_date=end_date,
        )

        query = query.paginate(page, pagination)

        posts = [model_to_message(item) for item in list(query)]

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
        message_type: Optional[MessageType] = None,
        content_types: Optional[Iterable[str]] = None,
        content_keys: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ) -> MessagesResponse:
        """
        Get many messages from the cache.
        """
        query = get_message_query(
            message_type=message_type,
            content_keys=content_keys,
            content_types=content_types,
            refs=refs,
            addresses=addresses,
            tags=tags,
            hashes=hashes,
            channels=channels,
            chains=chains,
            start_date=start_date,
            end_date=end_date,
        )

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
        query = MessageModel.select().where(MessageModel.item_hash == item_hash)

        if message_type:
            query = query.where(MessageModel.type == message_type.value)
        if channel:
            query = query.where(MessageModel.channel == channel)

        item = query.first()

        if item:
            return model_to_message(item)

        raise MessageNotFoundError(f"No such hash {item_hash}")

    async def watch_messages(
        self,
        message_type: Optional[MessageType] = None,
        content_types: Optional[Iterable[str]] = None,
        content_keys: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
    ) -> AsyncIterable[AlephMessage]:
        """
        Watch messages from the cache.
        """
        query = get_message_query(
            message_type=message_type,
            content_keys=content_keys,
            content_types=content_types,
            refs=refs,
            addresses=addresses,
            tags=tags,
            hashes=hashes,
            channels=channels,
            chains=chains,
            start_date=start_date,
            end_date=end_date,
        )

        async for item in query:
            yield model_to_message(item)


class DomainNode(MessageCache, AuthenticatedAlephClientBase):
    """
    A Domain Node is a queryable proxy for Aleph Messages that are stored in a database cache and/or in the Aleph
    network.

    It synchronizes with the network on a subset of the messages by listening to the network and storing the
    messages in the cache. The user may define the subset by specifying a channels, tags, senders, chains,
    message types, and/or a time window.
    """

    def __init__(
        self,
        session: AuthenticatedAlephClient,
        channels: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[Chain]] = None,
        message_type: Optional[MessageType] = None,
    ):
        super().__init__()
        self.session = session
        self.channels = channels
        self.tags = tags
        self.addresses = addresses
        self.chains = chains
        self.message_type = message_type

        # start listening to the network and storing messages in the cache
        asyncio.get_event_loop().create_task(
            self.listen_to(
                self.session.watch_messages(
                    channels=self.channels,
                    tags=self.tags,
                    addresses=self.addresses,
                    chains=self.chains,
                    message_type=self.message_type,
                )
            )
        )

        # synchronize with past messages
        asyncio.get_event_loop().run_until_complete(
            self.synchronize(
                channels=self.channels,
                tags=self.tags,
                addresses=self.addresses,
                chains=self.chains,
                message_type=self.message_type,
            )
        )

    async def __aenter__(self) -> "DomainNode":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        ...

    async def synchronize(
        self,
        channels: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[Chain]] = None,
        message_type: Optional[MessageType] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
    ):
        """
        Synchronize with past messages.
        """
        chunk_size = 200
        messages = []
        async for message in self.session.get_messages_iterator(
            channels=channels,
            tags=tags,
            addresses=addresses,
            chains=chains,
            message_type=message_type,
            start_date=start_date,
            end_date=end_date,
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
