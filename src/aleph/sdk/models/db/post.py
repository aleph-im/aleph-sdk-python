from peewee import CharField, DateTimeField, Model
from playhouse.sqlite_ext import JSONField

from .common import db, pydantic_json_dumps


class PostDBModel(Model):
    """
    A simple database model for storing AlephMessage objects.
    """

    original_item_hash = CharField(primary_key=True)
    item_hash = CharField()
    content = JSONField(json_dumps=pydantic_json_dumps)
    original_type = CharField()
    address = CharField()
    ref = CharField(null=True)
    channel = CharField(null=True)
    created = DateTimeField()
    last_updated = DateTimeField()
    tags = JSONField(json_dumps=pydantic_json_dumps, null=True)
    chain = CharField(5)

    class Meta:
        database = db
