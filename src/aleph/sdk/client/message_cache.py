import datetime
import logging
import typing
from pathlib import Path
from typing import (
    AsyncIterable,
    Coroutine,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Type,
    Union,
)

from aleph_message import MessagesResponse
from aleph_message.models import AlephMessage, ItemHash, MessageType, PostMessage
from peewee import SqliteDatabase
from playhouse.shortcuts import model_to_dict

from ..conf import settings
from ..db.aggregate import AggregateDBModel, aggregate_to_model
from ..db.message import (
    MessageDBModel,
    message_filter_to_query,
    message_to_model,
    model_to_message,
)
from ..db.post import (
    PostDBModel,
    message_to_post,
    model_to_post,
    post_filter_to_query,
    post_to_model,
)
from ..exceptions import InvalidCacheDatabaseSchema, MessageNotFoundError
from ..query.filters import MessageFilter, PostFilter
from ..query.responses import PostsResponse
from ..types import GenericMessage
from ..utils import Writable
from .abstract import AlephClient


class MessageCache(AlephClient):
    """
    A wrapper around a sqlite3 database for caching AlephMessage objects.

    It can be used independently of a DomainNode to implement any kind of caching strategy.
    """

    missing_posts: Dict[ItemHash, PostMessage] = {}
    """A dict of all posts by item_hash and their amend messages that are missing from the db."""

    def __init__(self, database_path: Optional[Union[str, Path]] = None):
        """
        Args:
            database_path: The path to the sqlite3 database file. If not provided, the default
                path will be used.

        Note:
            The database schema is automatically checked and updated if necessary.

        !!! warning
            :memory: databases are not supported, as they do not persist across connections.

        Raises:
            InvalidCacheDatabaseSchema: If the database schema does not match the expected message schema.
        """
        self.database_path: Path = (
            Path(database_path) if database_path else settings.CACHE_DATABASE_PATH
        )
        if not self.database_path.exists():
            self.database_path.parent.mkdir(parents=True, exist_ok=True)

        self.db = SqliteDatabase(self.database_path)
        MessageDBModel._meta.database = self.db
        PostDBModel._meta.database = self.db
        AggregateDBModel._meta.database = self.db

        self.db.connect(reuse_if_open=True)
        if not MessageDBModel.table_exists():
            self.db.create_tables([MessageDBModel])
        if not PostDBModel.table_exists():
            self.db.create_tables([PostDBModel])
        if not AggregateDBModel.table_exists():
            self.db.create_tables([AggregateDBModel])
        self._check_schema()
        self.db.close()

    def _check_schema(self):
        if sorted(MessageDBModel._meta.fields.keys()) != sorted(
            [col.name for col in self.db.get_columns(MessageDBModel._meta.table_name)]
        ):
            raise InvalidCacheDatabaseSchema(
                "MessageDBModel schema does not match MessageModel schema"
            )
        if sorted(PostDBModel._meta.fields.keys()) != sorted(
            [col.name for col in self.db.get_columns(PostDBModel._meta.table_name)]
        ):
            raise InvalidCacheDatabaseSchema(
                "PostDBModel schema does not match PostModel schema"
            )
        if sorted(AggregateDBModel._meta.fields.keys()) != sorted(
            [col.name for col in self.db.get_columns(AggregateDBModel._meta.table_name)]
        ):
            raise InvalidCacheDatabaseSchema(
                "AggregateDBModel schema does not match AggregateModel schema"
            )

    async def __aenter__(self):
        self.db.connect(reuse_if_open=True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.db.close()

    def __del__(self):
        self.db.close()

    def __getitem__(self, item_hash: ItemHash) -> Optional[AlephMessage]:
        item = MessageDBModel.get_or_none(MessageDBModel.item_hash == str(item_hash))
        return model_to_message(item) if item else None

    def __delitem__(self, item_hash: ItemHash):
        MessageDBModel.delete().where(
            MessageDBModel.item_hash == str(item_hash)
        ).execute()
        PostDBModel.delete().where(
            PostDBModel.original_item_hash == str(item_hash)
        ).execute()
        AggregateDBModel.delete().where(
            AggregateDBModel.original_message_hash == str(item_hash)
        ).execute()
        # delete stored files
        file_path = self._file_path(str(item_hash))
        if file_path.exists():
            file_path.unlink()

    def __contains__(self, item_hash: ItemHash) -> bool:
        return (
            MessageDBModel.select()
            .where(MessageDBModel.item_hash == str(item_hash))
            .exists()
        )

    def __len__(self):
        return MessageDBModel.select().count()

    def __iter__(self) -> Iterator[AlephMessage]:
        """
        Iterate over all messages in the db, the latest first.
        """
        for item in iter(MessageDBModel.select().order_by(-MessageDBModel.time)):
            yield model_to_message(item)

    def __repr__(self) -> str:
        return f"<MessageCache: {self.db}>"

    def __str__(self) -> str:
        return repr(self)

    @typing.overload
    def add(self, messages: Iterable[AlephMessage]): ...

    @typing.overload
    def add(self, messages: AlephMessage): ...

    def add(self, messages: Union[AlephMessage, Iterable[AlephMessage]]):
        """
        Add a message or a list of messages to the database. If the message is an amend,
        it will be applied to the original post. If the original post is not in the db,
        the amend message will be stored in memory until the original post is added.
        Aggregate message will be merged with any existing aggregate messages.

        Args:
            messages: A message or list of messages to add to the database.
        """
        if isinstance(messages, typing.get_args(AlephMessage)):
            messages = [messages]

        message_data = (message_to_model(message) for message in messages)
        MessageDBModel.insert_many(message_data).on_conflict_replace().execute()

        # Sort messages and insert posts first
        post_data = []
        amend_messages = []
        aggregate_messages = []
        forget_messages = []
        for message in messages:
            if message.type == MessageType.aggregate.value:
                aggregate_messages.append(message)
                continue
            if message.type == MessageType.forget.value:
                forget_messages.append(message)
                continue
            if message.type != MessageType.post.value:
                continue
            if message.content.type == "amend":
                amend_messages.append(message)
                continue

            post = post_to_model(message_to_post(message))
            post_data.append(post)

            # Check if we can now add any amend messages that had missing refs
            if message.item_hash in self.missing_posts:
                amend_messages += self.missing_posts.pop(message.item_hash)

        with self.db.atomic():
            PostDBModel.insert_many(post_data).on_conflict_replace().execute()

        self._handle_amends(amend_messages)

        self._handle_aggregates(aggregate_messages)

        self._handle_forgets(forget_messages)

    def _handle_amends(self, amend_messages: List[PostMessage]):
        post_data = []
        for amend in amend_messages:
            original_post = MessageDBModel.get_or_none(
                MessageDBModel.original_item_hash == amend.content.ref
            )
            if not original_post:
                latest_amend = self.missing_posts.get(ItemHash(amend.content.ref))
                if latest_amend and amend.time < latest_amend.time:
                    self.missing_posts[ItemHash(amend.content.ref)] = amend
                continue

            if amend.time < original_post.last_updated:
                continue

            original_post.item_hash = amend.item_hash
            original_post.content = amend.content.content
            original_post.original_item_hash = amend.content.ref
            original_post.original_type = amend.content.type
            original_post.address = amend.sender
            original_post.channel = amend.channel
            original_post.last_updated = amend.time
            post_data.append(model_to_dict(original_post))
        with self.db.atomic():
            PostDBModel.insert_many(post_data).on_conflict_replace().execute()

    def _handle_aggregates(self, aggregate_messages):
        aggregate_data = []
        for aggregate in aggregate_messages:
            existing_aggregate = AggregateDBModel.get_or_none(
                AggregateDBModel.address == aggregate.sender,
                AggregateDBModel.key == aggregate.content.key,
            )
            if not existing_aggregate:
                aggregate_data.append(aggregate_to_model(aggregate))
                continue
            existing_aggregate.time = datetime.datetime.fromisoformat(
                existing_aggregate.time
            )
            if aggregate.time > existing_aggregate.time:
                existing_aggregate.content.update(aggregate.content.content)
                existing_aggregate.time = aggregate.time
            elif existing_aggregate.content is None:
                existing_aggregate.content = aggregate.content.content
            else:
                existing_aggregate.content = dict(
                    aggregate.content.content, **existing_aggregate.content
                )
            data = model_to_dict(existing_aggregate)
            aggregate_data.append(data)
        with self.db.atomic():
            AggregateDBModel.insert_many(aggregate_data).on_conflict_replace().execute()

    def _handle_forgets(self, forget_messages):
        refs = [forget.content.ref for forget in forget_messages]
        with self.db.atomic():
            MessageDBModel.delete().where(MessageDBModel.item_hash.in_(refs)).execute()
            PostDBModel.delete().where(PostDBModel.item_hash.in_(refs)).execute()
            AggregateDBModel.delete().where(
                AggregateDBModel.original_message_hash.in_(refs)
            ).execute()

    @typing.overload
    def get(self, item_hashes: Iterable[ItemHash]) -> List[AlephMessage]: ...

    @typing.overload
    def get(self, item_hashes: ItemHash) -> Optional[AlephMessage]: ...

    def get(
        self, item_hashes: Union[ItemHash, Iterable[ItemHash]]
    ) -> List[AlephMessage]:
        """
        Get many messages from the db by their item hash.
        """
        if isinstance(item_hashes, ItemHash):
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
        Listen to a stream of messages and add them to the database.
        """

        async def _listen():
            async for message in message_stream:
                self.add(message)
                print(f"Added message {message.item_hash} to db")

        return _listen()

    async def fetch_aggregate(self, address: str, key: str) -> Dict[str, Dict]:
        item = (
            AggregateDBModel.select()
            .where(AggregateDBModel.address == address)
            .where(AggregateDBModel.key == key)
            .order_by(AggregateDBModel.key.desc())
            .get_or_none()
        )
        if not item:
            raise MessageNotFoundError(f"No such aggregate {address} {key}")
        return item.content

    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None
    ) -> Dict[str, Dict]:
        query = (
            AggregateDBModel.select()
            .where(AggregateDBModel.address == address)
            .order_by(AggregateDBModel.key.desc())
        )
        if keys:
            query = query.where(AggregateDBModel.key.in_(keys))
        return {item.key: item.content for item in list(query)}

    async def get_posts(
        self,
        pagination: int = 200,
        page: int = 1,
        post_filter: Optional[PostFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> PostsResponse:
        query = (
            post_filter_to_query(post_filter) if post_filter else PostDBModel.select()
        )

        query = query.paginate(page, pagination)

        posts = [model_to_post(item) for item in list(query)]

        return PostsResponse(
            posts=posts,
            pagination_page=page,
            pagination_per_page=pagination,
            pagination_total=query.count(),
            pagination_item="posts",
        )

    @staticmethod
    def _file_path(file_hash: str) -> Path:
        return settings.CACHE_FILES_PATH / Path(file_hash)

    async def download_file(self, file_hash: str) -> bytes:
        """
        Opens a file that has been locally stored by its hash.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        with open(self._file_path(file_hash), "rb") as f:
            return f.read()

    async def download_file_ipfs(self, file_hash: str) -> bytes:
        """
        Opens a file that has been locally stored by its IPFS hash.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        return await self.download_file(file_hash)

    async def download_file_to_buffer(
        self,
        file_hash: str,
        output_buffer: Writable[bytes],
    ) -> None:
        """
        Opens a file and writes it to a buffer.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        with open(self._file_path(file_hash), "rb") as f:
            output_buffer.write(f.read())

    async def download_file_to_buffer_ipfs(
        self,
        file_hash: str,
        output_buffer: Writable[bytes],
    ) -> None:
        """
        Opens a file and writes it to a buffer.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        await self.download_file_to_buffer(file_hash, output_buffer)

    async def add_file(self, file_hash: str, file_content: bytes):
        """
        Store a file locally by its hash.
        """
        if not self._file_path(file_hash).exists():
            self._file_path(file_hash).parent.mkdir(parents=True, exist_ok=True)
        with open(self._file_path(file_hash), "wb") as f:
            f.write(file_content)

    async def get_messages(
        self,
        pagination: int = 200,
        page: int = 1,
        message_filter: Optional[MessageFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> MessagesResponse:
        """
        Get and filter many messages from the database.
        """
        query = (
            message_filter_to_query(message_filter)
            if message_filter
            else MessageDBModel.select()
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
        Get a single message from the database by its item hash.
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
        Watch new messages as they are added to the database.
        """
        query = (
            message_filter_to_query(message_filter)
            if message_filter
            else MessageDBModel.select()
        )

        async for item in query:
            yield model_to_message(item)
