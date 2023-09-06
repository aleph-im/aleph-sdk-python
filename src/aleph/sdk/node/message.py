from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Union

from aleph_message import parse_message
from aleph_message.models import AlephMessage, MessageConfirmation, MessageType
from peewee import BooleanField, CharField, FloatField, IntegerField, Model
from playhouse.shortcuts import model_to_dict
from playhouse.sqlite_ext import JSONField

from aleph.sdk.node.common import PydanticField, db, pydantic_json_dumps


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
    message_types: Optional[Iterable[MessageType]] = None,
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
    if message_types:
        conditions.append(query_field("type", [type.value for type in message_types]))
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
