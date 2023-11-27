from typing import Dict

from aleph_message.models import AggregateMessage
from peewee import CharField, DateTimeField, Model
from playhouse.sqlite_ext import JSONField

from .common import pydantic_json_dumps


class AggregateDBModel(Model):
    """
    A simple database model for storing aleph.im Aggregates.
    """

    original_message_hash = CharField(primary_key=True)
    address = CharField(index=True)
    key = CharField()
    channel = CharField(null=True)
    content = JSONField(json_dumps=pydantic_json_dumps, null=True)
    time = DateTimeField()


def aggregate_to_model(message: AggregateMessage) -> Dict:
    return {
        "original_message_hash": str(message.item_hash),
        "address": str(message.sender),
        "key": str(message.content.key),
        "channel": message.channel,
        "content": message.content.content,
        "time": message.time,
    }
