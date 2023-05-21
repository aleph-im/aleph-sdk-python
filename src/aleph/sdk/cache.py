import json
from typing import Generic, List, Optional, TypeVar

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
    SqliteDatabase,
)

from aleph.sdk.conf import settings

db = SqliteDatabase(settings.CACHE_DB_PATH)

T = TypeVar("T")


class ComplexJSONField(Field, Generic[T]):
    """
    A field for storing complex types as JSON in a database. Uses json for serialization.
    """

    field_type = "text"
    complex_type: T

    def __init__(self, *args, **kwargs):
        self.complex_type = kwargs.pop("complex_type")
        super().__init__(*args, **kwargs)

    def db_value(self, value: T) -> str:
        return json.dumps(value)

    def python_value(self, value: str) -> T:
        return json.loads(value)


class MessageCacheDBModel(Model):
    """
    A simple database model for storing AlephMessage objects.
    """

    item_hash = CharField(primary_key=True)
    chain = CharField(5)
    type = CharField(9)
    sender = CharField()
    channel = CharField()
    confirmations: ComplexJSONField[
        Optional[List[MessageConfirmation]]
    ] = ComplexJSONField(complex_type=Optional[List[MessageConfirmation]])
    confirmed = BooleanField()
    signature = CharField()
    size = IntegerField()
    time = FloatField()
    item_type = CharField(7)
    hash_type = CharField(6)
    content: ComplexJSONField[BaseContent] = ComplexJSONField(complex_type=BaseContent)

    class Meta:
        database = db


class MessageCacheDB:
    """
    A wrapper around a database for storing AlephMessage objects.
    """

    def __init__(self):
        print("init cache")
        print(db.connect())
        print(db.create_tables([MessageCacheDBModel]))

    def __del__(self):
        db.close()

    def __getitem__(self, item_hash) -> Optional[AlephMessage]:
        try:
            item = MessageCacheDBModel.get(MessageCacheDBModel.item_hash == item_hash)
        except MessageCacheDBModel.DoesNotExist:
            return None
        if item.type == MessageType.post.value:
            return PostMessage.from_orm(item)
        elif item.type == MessageType.aggregate.value:
            return AggregateMessage.from_orm(item)
        elif item.type == MessageType.store.value:
            return StoreMessage.from_orm(item)
        elif item.type == MessageType.forget.value:
            return ForgetMessage.from_orm(item)
        elif item.type == MessageType.program.value:
            raise ProgramMessage.from_orm(item)
        else:
            raise ValueError(f"Unknown message type {item.type}")

    def __setitem__(self, item_hash, message: AlephMessage):
        MessageCacheDBModel.create(
            item_hash=message.item_hash,
            chain=message.chain.value,
            type=message.type.value,
            sender=message.sender,
            channel=message.channel,
            confirmations=message.confirmations,
            confirmed=message.confirmed,
            signature=message.signature,
            size=message.size,
            time=message.time,
            item_type=message.item_type,
            hash_type=message.hash_type,
            content=message.content,
        )

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
