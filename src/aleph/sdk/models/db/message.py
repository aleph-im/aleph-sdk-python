from aleph_message.models import MessageConfirmation
from peewee import BooleanField, CharField, FloatField, IntegerField, Model
from playhouse.sqlite_ext import JSONField

from .common import PydanticField, db, pydantic_json_dumps


class MessageDBModel(Model):
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
