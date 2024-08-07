from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from aleph_message.models import (
    AlephMessage,
    Chain,
    ItemHash,
    ItemType,
    MessageConfirmation,
)
from pydantic import BaseModel, Field


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


class PaginationResponse(BaseModel):
    pagination_page: int
    pagination_total: int
    pagination_per_page: int
    pagination_item: str


class PostsResponse(PaginationResponse):
    """Response from an aleph.im node API on the path /api/v0/posts.json"""

    posts: List[Post]
    pagination_item = "posts"


class MessagesResponse(PaginationResponse):
    """Response from an aleph.im node API on the path /api/v0/messages.json"""

    messages: List[AlephMessage]
    pagination_item = "messages"


class PriceResponse(BaseModel):
    """Response from an aleph.im node API on the path /api/v0/price/{item_hash}"""

    required_tokens: float
    payment_type: str
