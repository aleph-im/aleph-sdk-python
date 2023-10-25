from typing import Any, Dict, Iterable

from aleph_message import parse_message
from aleph_message.models import AlephMessage, MessageConfirmation
from peewee import BooleanField, CharField, FloatField, IntegerField, Model
from playhouse.shortcuts import model_to_dict
from playhouse.sqlite_ext import JSONField

from ..query.filters import MessageFilter
from .common import PydanticField, pydantic_json_dumps


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
        MessageDBModel.tags,
        MessageDBModel.ref,
        MessageDBModel.key,
        MessageDBModel.content_type,
    ]

    item_dict = model_to_dict(item, exclude=to_exclude)
    return parse_message(item_dict)


def query_field(field_name, field_values: Iterable[str]):
    field = getattr(MessageDBModel, field_name)
    values = list(field_values)

    if len(values) == 1:
        return field == values[0]
    return field.in_(values)


def message_filter_to_query(filter: MessageFilter) -> MessageDBModel:
    query = MessageDBModel.select().order_by(MessageDBModel.time.desc())
    conditions = []
    if filter.message_types:
        conditions.append(
            query_field("type", [type.value for type in filter.message_types])
        )
    if filter.content_keys:
        conditions.append(query_field("key", filter.content_keys))
    if filter.content_types:
        conditions.append(query_field("content_type", filter.content_types))
    if filter.refs:
        conditions.append(query_field("ref", filter.refs))
    if filter.addresses:
        conditions.append(query_field("sender", filter.addresses))
    if filter.tags:
        for tag in filter.tags:
            conditions.append(MessageDBModel.tags.contains(tag))
    if filter.hashes:
        conditions.append(query_field("item_hash", filter.hashes))
    if filter.channels:
        conditions.append(query_field("channel", filter.channels))
    if filter.chains:
        conditions.append(query_field("chain", filter.chains))
    if filter.start_date:
        conditions.append(MessageDBModel.time >= filter.start_date)
    if filter.end_date:
        conditions.append(MessageDBModel.time <= filter.end_date)

    if conditions:
        query = query.where(*conditions)
    return query
