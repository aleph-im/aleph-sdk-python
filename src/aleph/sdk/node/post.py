from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Union

from aleph_message.models import PostMessage
from peewee import CharField, DateTimeField, Model
from playhouse.shortcuts import model_to_dict
from playhouse.sqlite_ext import JSONField

from aleph.sdk.models import Post
from aleph.sdk.node.common import db, pydantic_json_dumps


class PostModel(Model):
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


def post_to_model(post: Post) -> Dict:
    return {
        "item_hash": str(post.item_hash),
        "content": post.content,
        "original_item_hash": str(post.original_item_hash),
        "original_type": post.original_type,
        "address": post.address,
        "ref": post.ref,
        "channel": post.channel,
        "created": post.created,
        "last_updated": post.last_updated,
    }


def message_to_post(message: PostMessage) -> Post:
    return Post.parse_obj(
        {
            "item_hash": str(message.item_hash),
            "content": message.content,
            "original_item_hash": str(message.item_hash),
            "original_type": message.content.type
            if hasattr(message.content, "type")
            else None,
            "address": message.sender,
            "ref": message.content.ref if hasattr(message.content, "ref") else None,
            "channel": message.channel,
            "created": datetime.fromtimestamp(message.time),
            "last_updated": datetime.fromtimestamp(message.time),
        }
    )


def model_to_post(item: Any) -> Post:
    to_exclude = [PostModel.tags, PostModel.chain]
    return Post.parse_obj(model_to_dict(item, exclude=to_exclude))


def query_field(field_name, field_values: Iterable[str]):
    field = getattr(PostModel, field_name)
    values = list(field_values)

    if len(values) == 1:
        return field == values[0]
    return field.in_(values)


def get_post_query(
    types: Optional[Iterable[str]] = None,
    refs: Optional[Iterable[str]] = None,
    addresses: Optional[Iterable[str]] = None,
    tags: Optional[Iterable[str]] = None,
    hashes: Optional[Iterable[str]] = None,
    channels: Optional[Iterable[str]] = None,
    chains: Optional[Iterable[str]] = None,
    start_date: Optional[Union[datetime, float]] = None,
    end_date: Optional[Union[datetime, float]] = None,
):
    query = PostModel.select().order_by(PostModel.created.desc())
    conditions = []
    if types:
        conditions.append(query_field("original_type", types))
    if refs:
        conditions.append(query_field("ref", refs))
    if addresses:
        conditions.append(query_field("address", addresses))
    if tags:
        for tag in tags:
            conditions.append(PostModel.tags.contains(tag))
    if hashes:
        conditions.append(query_field("item_hash", hashes))
    if channels:
        conditions.append(query_field("channel", channels))
    if chains:
        conditions.append(query_field("chain", chains))
    if start_date:
        conditions.append(PostModel.time >= start_date)
    if end_date:
        conditions.append(PostModel.time <= end_date)

    if conditions:
        query = query.where(*conditions)
    return query
