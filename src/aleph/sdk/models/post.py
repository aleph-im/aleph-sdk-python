from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from aleph_message.models import ItemHash, PostMessage
from playhouse.shortcuts import model_to_dict
from pydantic import BaseModel, Field

from .common import (
    PaginationResponse,
    _date_field_to_float,
    query_db_field,
    serialize_list,
)
from .db.post import PostDBModel


class Post(BaseModel):
    """
    A post is a type of message that can be updated. Over the get_posts API
    we get the latest version of a post.
    """

    item_hash: ItemHash = Field(description="Hash of the content (sha256 by default)")
    content: Dict[str, Any] = Field(
        description="The content.content of the POST message"
    )
    original_item_hash: ItemHash = Field(
        description="Hash of the original content (sha256 by default)"
    )
    original_type: str = Field(
        description="The original, user-generated 'content-type' of the POST message"
    )
    address: str = Field(description="The address of the sender of the POST message")
    ref: Optional[str] = Field(description="Other message referenced by this one")
    channel: Optional[str] = Field(
        description="The channel where the POST message was published"
    )
    created: datetime = Field(description="The time when the POST message was created")
    last_updated: datetime = Field(
        description="The time when the POST message was last updated"
    )

    class Config:
        allow_extra = False
        orm_mode = True

    @classmethod
    def from_orm(cls, obj: Any) -> "Post":
        if isinstance(obj, PostDBModel):
            return Post.parse_obj(model_to_dict(obj))
        return super().from_orm(obj)

    @classmethod
    def from_message(cls, message: PostMessage) -> "Post":
        return Post.parse_obj(
            {
                "item_hash": str(message.item_hash),
                "content": message.content.content,
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


class PostsResponse(PaginationResponse):
    """Response from an Aleph node API on the path /api/v0/posts.json"""

    posts: List[Post]
    pagination_item = "posts"


class PostFilter:
    """
    A collection of filters that can be applied on post queries.

    """

    types: Optional[Iterable[str]]
    refs: Optional[Iterable[str]]
    addresses: Optional[Iterable[str]]
    tags: Optional[Iterable[str]]
    hashes: Optional[Iterable[str]]
    channels: Optional[Iterable[str]]
    chains: Optional[Iterable[str]]
    start_date: Optional[Union[datetime, float]]
    end_date: Optional[Union[datetime, float]]

    def __init__(
        self,
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
        self.types = types
        self.refs = refs
        self.addresses = addresses
        self.tags = tags
        self.hashes = hashes
        self.channels = channels
        self.chains = chains
        self.start_date = start_date
        self.end_date = end_date

    def as_http_params(self) -> Dict[str, str]:
        """Convert the filters into a dict that can be used by an `aiohttp` client
        as `params` to build the HTTP query string.
        """

        partial_result = {
            "types": serialize_list(self.types),
            "refs": serialize_list(self.refs),
            "addresses": serialize_list(self.addresses),
            "tags": serialize_list(self.tags),
            "hashes": serialize_list(self.hashes),
            "channels": serialize_list(self.channels),
            "chains": serialize_list(self.chains),
            "startDate": _date_field_to_float(self.start_date),
            "endDate": _date_field_to_float(self.end_date),
        }

        # Ensure all values are strings.
        result: Dict[str, str] = {}

        # Drop empty values
        for key, value in partial_result.items():
            if value:
                assert isinstance(value, str), f"Value must be a string: `{value}`"
                result[key] = value

        return result

    def as_db_query(self):
        query = PostDBModel.select().order_by(PostDBModel.created.desc())
        conditions = []
        if self.types:
            conditions.append(query_db_field(PostDBModel, "original_type", self.types))
        if self.refs:
            conditions.append(query_db_field(PostDBModel, "ref", self.refs))
        if self.addresses:
            conditions.append(query_db_field(PostDBModel, "address", self.addresses))
        if self.tags:
            for tag in self.tags:
                conditions.append(PostDBModel.tags.contains(tag))
        if self.hashes:
            conditions.append(query_db_field(PostDBModel, "item_hash", self.hashes))
        if self.channels:
            conditions.append(query_db_field(PostDBModel, "channel", self.channels))
        if self.chains:
            conditions.append(query_db_field(PostDBModel, "chain", self.chains))
        if self.start_date:
            conditions.append(PostDBModel.time >= self.start_date)
        if self.end_date:
            conditions.append(PostDBModel.time <= self.end_date)

        if conditions:
            query = query.where(*conditions)
        return query
