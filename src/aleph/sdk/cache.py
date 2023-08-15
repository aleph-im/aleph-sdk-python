import json
import logging
from datetime import datetime
from functools import partial
from typing import (
    Any,
    AsyncIterable,
    Coroutine,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
)

import aleph_message.models
from aleph_message import MessagesResponse
from aleph_message.models import (
    AlephMessage,
    ItemHash,
    MessageConfirmation,
    MessageType,
)
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

from aleph.sdk.base import AlephClientBase
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import MessageNotFoundError
from aleph.sdk.types import GenericMessage

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
    return aleph_message.parse_message(item_dict)


class MessageCache(AlephClientBase):
    """
    A wrapper around a sqlite3 database for storing AlephMessage objects.
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

    def add(self, messages: Union[AlephMessage, Iterable[AlephMessage]]):
        if isinstance(messages, AlephMessage):
            messages = [messages]

        data_source = (message_to_model(message) for message in messages)
        MessageModel.insert_many(data_source).on_conflict_replace().execute()

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
        query = (
            MessageModel.select()
            .where(MessageModel.sender == address)
            .where(MessageModel.key == key)
            .order_by(MessageModel.time.desc())
            .limit(limit)
        )
        return {item.key: model_to_message(item) for item in list(query)}

    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None, limit: int = 100
    ) -> Dict[str, Dict]:
        query = (
            MessageModel.select()
            .where(MessageModel.sender == address)
            .order_by(MessageModel.time.desc())
        )
        if keys:
            query = query.where(MessageModel.key.in_(keys))
        query = query.limit(limit)
        return {item.key: model_to_message(item) for item in list(query)}

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
    ) -> Dict[str, Dict]:
        query = (
            MessageModel.select()
            .where(MessageModel.type == MessageType.post.value)
            .order_by(MessageModel.time.desc())
        )

        conditions = []

        if types:
            conditions.append(query_message_types(types))
        if refs:
            conditions.append(query_refs(refs))
        if addresses:
            conditions.append(query_addresses(addresses))
        if tags:
            for tag in tags:
                conditions.append(MessageModel.tags.contains(tag))
        if hashes:
            conditions.append(query_hashes(hashes))
        if channels:
            conditions.append(query_channels(channels))
        if chains:
            conditions.append(query_chains(chains))
        if start_date:
            conditions.append(MessageModel.time >= start_date)
        if end_date:
            conditions.append(MessageModel.time <= end_date)

        if conditions:
            query = query.where(*conditions)

        query = query.paginate(page, pagination)

        return {item.key: model_to_message(item) for item in list(query)}

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
        query = MessageModel.select().order_by(MessageModel.time.desc())

        conditions = []

        if message_type:
            conditions.append(query_message_types(message_type))
        if content_types:
            conditions.append(query_content_types(content_types))
        if content_keys:
            conditions.append(query_content_keys(content_keys))
        if refs:
            conditions.append(query_refs(refs))
        if addresses:
            conditions.append(query_addresses(addresses))
        if tags:
            for tag in tags:
                conditions.append(MessageModel.tags.contains(tag))
        if hashes:
            conditions.append(query_hashes(hashes))
        if channels:
            conditions.append(query_channels(channels))
        if chains:
            conditions.append(query_chains(chains))
        if start_date:
            conditions.append(MessageModel.time >= start_date)
        if end_date:
            conditions.append(MessageModel.time <= end_date)

        if conditions:
            query = query.where(*conditions)

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
        query = MessageModel.select().order_by(MessageModel.time.desc())

        conditions = []

        if message_type:
            conditions.append(MessageModel.type == message_type.value)
        if content_types:
            conditions.append(query_content_types(content_types))
        if refs:
            conditions.append(query_refs(refs))
        if addresses:
            conditions.append(query_addresses(addresses))
        if tags:
            for tag in tags:
                conditions.append(MessageModel.tags.contains(tag))
        if hashes:
            conditions.append(query_hashes(hashes))
        if channels:
            conditions.append(query_channels(channels))
        if chains:
            conditions.append(query_chains(chains))
        if start_date:
            conditions.append(MessageModel.time >= start_date)
        if end_date:
            conditions.append(MessageModel.time <= end_date)

        if conditions:
            query = query.where(*conditions)

        async for item in query:
            yield model_to_message(item)


def query_message_types(message_types: Union[str, Iterable[str]]):
    if isinstance(message_types, str):
        return MessageModel.type == message_types
    return MessageModel.type.in_(message_types)


def query_content_types(content_types: Union[str, Iterable[str]]):
    if isinstance(content_types, str):
        return MessageModel.content_type == content_types
    return MessageModel.content_type.in_(content_types)


def query_content_keys(content_keys: Union[str, Iterable[str]]):
    if isinstance(content_keys, str):
        return MessageModel.key == content_keys
    return MessageModel.key.in_(content_keys)


def query_refs(refs: Union[str, Iterable[str]]):
    if isinstance(refs, str):
        return MessageModel.ref == refs
    return MessageModel.ref.in_(refs)


def query_addresses(addresses: Union[str, Iterable[str]]):
    if isinstance(addresses, str):
        return MessageModel.sender == addresses
    return MessageModel.sender.in_(addresses)


def query_hashes(hashes: Union[ItemHash, Iterable[ItemHash]]):
    if isinstance(hashes, ItemHash):
        return MessageModel.item_hash == hashes
    return MessageModel.item_hash.in_(hashes)


def query_channels(channels: Union[str, Iterable[str]]):
    if isinstance(channels, str):
        return MessageModel.channel == channels
    return MessageModel.channel.in_(channels)


def query_chains(chains: Union[str, Iterable[str]]):
    if isinstance(chains, str):
        return MessageModel.chain == chains
    return MessageModel.chain.in_(chains)
