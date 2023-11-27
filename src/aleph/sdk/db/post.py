from typing import Any, Dict, Iterable

from aleph_message.models import MessageConfirmation, PostMessage
from peewee import BooleanField, CharField, DateTimeField, IntegerField, Model
from playhouse.shortcuts import model_to_dict
from playhouse.sqlite_ext import JSONField

from ..query.filters import PostFilter
from ..query.responses import Post
from .common import PydanticField, pydantic_json_dumps


class PostDBModel(Model):
    """
    A simple database model for storing AlephMessage objects.
    """

    original_item_hash = CharField(primary_key=True)
    original_type = CharField()
    original_signature = CharField()
    item_hash = CharField()
    chain = CharField(5)
    type = CharField(index=True)
    sender = CharField()
    channel = CharField(null=True)
    confirmations: PydanticField[MessageConfirmation] = PydanticField(
        type=MessageConfirmation, null=True
    )
    confirmed = BooleanField()
    signature = CharField()
    size = IntegerField(null=True)
    time = DateTimeField()
    item_type = CharField(7)
    item_content = CharField(null=True)
    content = JSONField(json_dumps=pydantic_json_dumps)
    tags = JSONField(json_dumps=pydantic_json_dumps, null=True)
    key = CharField(null=True)
    ref = CharField(null=True)
    content_type = CharField(null=True)

    @classmethod
    def get_all_fields(cls):
        return cls._meta.sorted_field_names


def post_to_model(post: Post) -> Dict:
    return {
        "item_hash": str(post.original_item_hash),
        "chain": post.chain.value,
        "type": post.type,
        "sender": post.sender,
        "channel": post.channel,
        "confirmations": post.confirmations[0] if post.confirmations else None,
        "confirmed": post.confirmed,
        "signature": post.signature,
        "size": post.size,
        "time": post.time,
        "original_item_hash": str(post.original_item_hash),
        "original_type": post.original_type if post.original_type else post.type,
        "original_signature": post.original_signature
        if post.original_signature
        else post.signature,
        "item_type": post.item_type,
        "item_content": post.item_content,
        "content": post.content,
        "tags": post.content.content.get("tags", None)
        if hasattr(post.content, "content")
        else None,
        "ref": post.ref,
    }


def message_to_post(message: PostMessage) -> Post:
    return Post(
        chain=message.chain,
        item_hash=message.item_hash,
        sender=message.sender,
        type=message.content.type,
        channel=message.channel,
        confirmed=message.confirmed if message.confirmed else False,
        confirmations=message.confirmations if message.confirmations else [],
        content=message.content,
        item_content=message.item_content,
        item_type=message.item_type,
        signature=message.signature,
        size=message.size if message.size else len(message.content.json().encode()),
        time=message.time,
        original_item_hash=message.item_hash,
        original_signature=message.signature,
        original_type=message.content.type,
        hash=message.item_hash,
        ref=message.content.ref,
    )


def model_to_post(item: Any) -> Post:
    to_exclude = [PostDBModel.tags]
    model_dict = model_to_dict(item, exclude=to_exclude)
    model_dict["confirmations"] = (
        [model_dict["confirmations"]] if model_dict["confirmations"] else []
    )
    model_dict["hash"] = model_dict["item_hash"]
    return Post.parse_obj(model_dict)


def query_field(field_name, field_values: Iterable[str]):
    field = getattr(PostDBModel, field_name)
    values = list(field_values)

    if len(values) == 1:
        return field == values[0]
    return field.in_(values)


def post_filter_to_query(filter: PostFilter) -> PostDBModel:
    query = PostDBModel.select().order_by(PostDBModel.time.desc())
    conditions = []
    if filter.types:
        conditions.append(query_field("type", filter.types))
    if filter.refs:
        conditions.append(query_field("ref", filter.refs))
    if filter.addresses:
        conditions.append(query_field("sender", filter.addresses))
    if filter.tags:
        for tag in filter.tags:
            conditions.append(PostDBModel.tags.contains(tag))
    if filter.hashes:
        conditions.append(query_field("original_item_hash", filter.hashes))
    if filter.channels:
        conditions.append(query_field("channel", filter.channels))
    if filter.chains:
        conditions.append(query_field("chain", filter.chains))
    if filter.start_date:
        conditions.append(PostDBModel.time >= filter.start_date)
    if filter.end_date:
        conditions.append(PostDBModel.time <= filter.end_date)

    if conditions:
        query = query.where(*conditions)
    return query
