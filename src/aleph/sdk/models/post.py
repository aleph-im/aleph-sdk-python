from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from aleph_message.models import Chain, ItemHash, ItemType, MessageConfirmation
from pydantic import BaseModel, Field

from .common import PaginationResponse, _date_field_to_float, serialize_list


class Post(BaseModel):
    """
    A post is a type of message that can be updated. Over the get_posts API
    we get the latest version of a post.
    """

    chain: Chain = Field(description="Blockchain this post is associated with")
    item_hash: ItemHash = Field(description="Unique hash for this post")
    sender: str = Field(description="Address of the sender")
    type: str = Field(description="Type of the POST message")
    channel: Optional[str] = Field(description="Channel this post is associated with")
    confirmed: bool = Field(description="Whether the post is confirmed or not")
    content: Dict[str, Any] = Field(description="The content of the POST message")
    item_content: Optional[str] = Field(
        description="The POSTs content field as serialized JSON, if of type inline"
    )
    item_type: ItemType = Field(
        description="Type of the item content, usually 'inline' or 'storage' for POSTs"
    )
    signature: Optional[str] = Field(
        description="Cryptographic signature of the message by the sender"
    )
    size: int = Field(description="Size of the post")
    time: float = Field(description="Timestamp of the post")
    confirmations: List[MessageConfirmation] = Field(
        description="Number of confirmations"
    )
    original_item_hash: ItemHash = Field(description="Hash of the original content")
    original_signature: Optional[str] = Field(
        description="Cryptographic signature of the original message"
    )
    original_type: str = Field(description="The original type of the message")
    hash: ItemHash = Field(description="Hash of the original item")
    ref: Optional[Union[str, Any]] = Field(
        description="Other message referenced by this one"
    )

    class Config:
        allow_extra = False


class PostsResponse(PaginationResponse):
    """Response from an aleph.im node API on the path /api/v0/posts.json"""

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
