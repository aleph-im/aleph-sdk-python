import json
from typing import Generic, List, Optional, TypeVar, Union

from aleph_message.models import (
    AggregateMessage,
    AlephMessage,
    BaseContent,
    ForgetMessage,
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
    SqliteDatabase
)
from playhouse.shortcuts import model_to_dict
from pydantic import BaseModel

from aleph.sdk.conf import settings

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


class DictJsonField(Field):
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


class MessageCacheDBModel(Model):
    """
    A simple database model for storing AlephMessage objects.
    """

    item_hash = CharField(primary_key=True)
    chain = CharField(5)
    type = CharField(9)
    sender = CharField()
    channel = CharField(null=True)
    confirmations: PydanticField[MessageConfirmation] = PydanticField(type=MessageConfirmation, null=True)
    confirmed = BooleanField(null=True)
    signature = CharField(null=True)
    size = IntegerField(null=True)
    time = FloatField()
    item_type = CharField(7)
    item_content = CharField(null=True)
    hash_type = CharField(6, null=True)
    content = DictJsonField()
    forgotten_by = CharField(null=True)

    class Meta:
        database = db


class MessageCache:
    """
    A wrapper around an sqlite3 database for storing AlephMessage objects.
    """
    def __init__(self):
        print("init cache")
        db.connect()
        db.create_tables([MessageCacheDBModel])

    def __del__(self):
        db.close()

    def __getitem__(self, item_hash) -> Optional[AlephMessage]:
        try:
            item = MessageCacheDBModel.get(MessageCacheDBModel.item_hash == str(item_hash))
            item.confirmations = [item.confirmations] if item.confirmations else []
            item.forgotten_by = [item.forgotten_by] if item.forgotten_by else None
        except MessageCacheDBModel.DoesNotExist:
            return None
        if item.type == MessageType.post.value:
            return PostMessage.parse_obj(model_to_dict(item))
        elif item.type == MessageType.aggregate.value:
            return AggregateMessage.parse_obj(model_to_dict(item))
        elif item.type == MessageType.store.value:
            return StoreMessage.parse_obj(model_to_dict(item))
        elif item.type == MessageType.forget.value:
            return ForgetMessage.parse_obj(model_to_dict(item))
        elif item.type == MessageType.program.value:
            raise ProgramMessage.parse_obj(model_to_dict(item))
        else:
            raise ValueError(f"Unknown message type {item.type}")

    def __setitem__(self, item_hash, message: AlephMessage):
        MessageCacheDBModel.insert(
            item_hash=str(message.item_hash),
            chain=message.chain.value,
            type=message.type.value,
            sender=message.sender,
            channel=message.channel,
            confirmations=message.confirmations[0] if message.confirmations else None,
            confirmed=message.confirmed,
            signature=message.signature,
            size=message.size,
            time=message.time,
            item_type=message.item_type,
            item_content=message.item_content,
            hash_type=message.hash_type,
            content=message.content,
            forgotten_by=message.forgotten_by[0] if message.forgotten_by else None,
        ).on_conflict_replace().execute()

    def __contains__(self, item_hash):
        return MessageCacheDBModel.select().where(MessageCacheDBModel.item_hash == item_hash).exists()

    def __len__(self):
        return MessageCacheDBModel.select().count()

    def __iter__(self):
        return iter(MessageCacheDBModel.select())

    def __delitem__(self, item_hash):
        MessageCacheDBModel.delete().where(MessageCacheDBModel.item_hash == item_hash).execute()

    def __repr__(self):
        return f"<MessageCache: {db}>"

    def __str__(self):
        return repr(self)

    def add(self, message: AlephMessage):
        self[message.item_hash] = message

    def get(self, item_hash) -> Optional[AlephMessage]:
        return self[item_hash]
