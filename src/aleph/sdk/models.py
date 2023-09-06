from datetime import datetime
from typing import Any, Dict, List, Optional

from aleph_message.models import AlephMessage, ItemHash
from pydantic import BaseModel, Field


class PaginationResponse(BaseModel):
    pagination_page: int
    pagination_total: int
    pagination_per_page: int
    pagination_item: str


class MessagesResponse(PaginationResponse):
    """Response from an Aleph node API on the path /api/v0/messages.json"""

    messages: List[AlephMessage]
    pagination_item = "messages"


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
    channel: Optional[str] = Field(description="The channel where the POST message was published")
    created: datetime = Field(description="The time when the POST message was created")
    last_updated: datetime = Field(
        description="The time when the POST message was last updated"
    )

    class Config:
        allow_extra = False


class PostsResponse(PaginationResponse):
    """Response from an Aleph node API on the path /api/v0/posts.json"""

    posts: List[Post]
    pagination_item = "posts"
