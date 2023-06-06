import json
import logging
from datetime import datetime
from typing import (
    Any,
    AsyncIterable,
    Coroutine,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
)

from aleph_message import MessagesResponse
from aleph_message.models import (
    AggregateMessage,
    AlephMessage,
    ForgetMessage,
    ItemHash,
    MessageConfirmation,
    MessageType,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from peewee import (
    BooleanField,
    CharField,
    Field,
    FloatField,
    IntegerField,
    Model,
    SqliteDatabase,
    chunked,
)
from playhouse.shortcuts import model_to_dict
from pydantic import BaseModel

from aleph.sdk.conf import settings
from aleph.sdk.exceptions import MessageNotFoundError
from aleph.sdk.interface import AlephClientInterface
from aleph.sdk.types import GenericMessage

db = SqliteDatabase(settings.CACHE_DB_PATH)

T = TypeVar("T", bound=BaseModel)


class JSONDictEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BaseModel):
            return obj.dict()
        return json.JSONEncoder.default(self, obj)


class PydanticField(Field, Generic[T]):
    """
    A field for storing pydantic model types as JSON in a database. Uses json for serialization.
    """

    field_type = "text"
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


class JsonField(Field):
    """
    A field for storing dicts as JSON in a database. Uses json for serialization.
    """

    field_type = "text"

    def db_value(self, value: Optional[dict]) -> Optional[str]:
        if value is None:
            return None
        return json.dumps(value, cls=JSONDictEncoder)

    def python_value(self, value: Optional[str]) -> Optional[dict]:
        if value is None:
            return None
        return json.loads(value)


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
    content = JsonField()
    forgotten_by = CharField(null=True)
    tags = JsonField(null=True)
    key = CharField(null=True)
    ref = CharField(null=True)
    post_type = CharField(null=True)

    class Meta:
        database = db


class MessageCache(AlephClientInterface):
    """
    A wrapper around an sqlite3 database for storing AlephMessage objects.
    """

    def __init__(self):
        if db.is_closed():
            db.connect()
            db.create_tables([MessageModel])

    def __del__(self):
        db.close()

    def __getitem__(self, item_hash) -> Optional[AlephMessage]:
        try:
            item = MessageModel.get(MessageModel.item_hash == str(item_hash))
        except MessageModel.DoesNotExist:
            return None
        return model_to_message(item)

    def __setitem__(self, item_hash, message: AlephMessage):
        MessageModel.insert(**message_to_model(message)).on_conflict_replace().execute()

    def __delitem__(self, item_hash):
        MessageModel.delete().where(MessageModel.item_hash == item_hash).execute()

    def __contains__(self, item_hash):
        return MessageModel.select().where(MessageModel.item_hash == item_hash).exists()

    def __len__(self):
        return MessageModel.select().count()

    def __iter__(self):
        return iter(MessageModel.select())

    def __repr__(self):
        return f"<MessageCache: {db}>"

    def __str__(self):
        return repr(self)

    def add_many(self, messages: Union[AlephMessage, List[AlephMessage]]):
        if not isinstance(messages, list):
            messages = [messages]

        data_source = (message_to_model(message) for message in messages)
        with db.atomic():
            for batch in chunked(data_source, 100):
                MessageModel.insert_many(batch).on_conflict_replace().execute()

    def get_many(
        self, item_hashes: Union[Union[ItemHash, str], List[Union[ItemHash, str]]]
    ) -> List[AlephMessage]:
        """
        Get many messages from the cache by their item hash.
        """
        if not isinstance(item_hashes, list):
            item_hashes = [item_hashes]
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
                self.add_many(message)
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
            conditions.append(query_post_types(types))
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
            conditions.append(MessageModel.type == message_type.value)
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
        "key": message.key if hasattr(message, "key") else None,
        "ref": message.content.ref if hasattr(message.content, "ref") else None,
        "post_type": message.content.type if hasattr(message.content, "type") else None,
    }


def model_to_message(item: Any) -> AlephMessage:
    item.confirmations = [item.confirmations] if item.confirmations else []
    item.forgotten_by = [item.forgotten_by] if item.forgotten_by else None

    item_dict = model_to_dict(
        item,
        exclude=[
            MessageModel.tags,
            MessageModel.key,
            MessageModel.ref,
            MessageModel.post_type,
        ],
    )

    if item.type == MessageType.post.value:
        return PostMessage.parse_obj(item_dict)
    elif item.type == MessageType.aggregate.value:
        return AggregateMessage.parse_obj(item_dict)
    elif item.type == MessageType.store.value:
        return StoreMessage.parse_obj(item_dict)
    elif item.type == MessageType.forget.value:
        return ForgetMessage.parse_obj(item_dict)
    elif item.type == MessageType.program.value:
        return ProgramMessage.parse_obj(item_dict)
    else:
        raise ValueError(f"Unknown message type {item.type}")


def query_post_types(types):
    types = list(types)
    if len(types) == 1:
        return MessageModel.content_type == types[0]
    return MessageModel.content_type.in_(types)


def query_content_types(content_types):
    content_types = list(content_types)
    if len(content_types) == 1:
        return MessageModel.content_type == content_types[0]
    return MessageModel.content_type.in_(content_types)


def query_content_keys(content_keys):
    content_keys = list(content_keys)
    if len(content_keys) == 1:
        return MessageModel.key == content_keys[0]
    return MessageModel.key.in_(content_keys)


def query_refs(refs):
    refs = list(refs)
    if len(refs) == 1:
        return MessageModel.ref == refs[0]
    return MessageModel.ref.in_(refs)


def query_addresses(addresses):
    addresses = list(addresses)
    if len(addresses) == 1:
        return MessageModel.sender == addresses[0]
    return MessageModel.sender.in_(addresses)


def query_hashes(hashes):
    hashes = list(hashes)
    if len(hashes) == 1:
        return MessageModel.item_hash == hashes[0]
    return MessageModel.item_hash.in_(hashes)


def query_channels(channels):
    channels = list(channels)
    if len(channels) == 1:
        return MessageModel.channel == channels[0]
    return MessageModel.channel.in_(channels)


def query_chains(chains):
    chains = list(chains)
    if len(chains) == 1:
        return MessageModel.chain == chains[0]
    return MessageModel.chain.in_(chains)
