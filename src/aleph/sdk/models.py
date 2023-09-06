from typing import List, Optional, Any, Dict, Union

from aleph_message.models import AlephMessage, BaseMessage, ItemHash, ChainRef
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


class Post(BaseMessage):
    """
    A post is a type of message that can be updated. Over the get_posts API
    we get the latest version of a post.
    """
    hash: ItemHash = Field(description="Hash of the content (sha256 by default)")
    original_item_hash: ItemHash = Field(description="Hash of the original content (sha256 by default)")
    original_signature: Optional[str] = Field(
        description="Cryptographic signature of the original message by the sender"
    )
    original_type: str = Field(description="The original, user-generated 'content-type' of the POST message")
    content: Dict[str, Any] = Field(description="The content.content of the POST message")
    type: str = Field(description="The content.type of the POST message")
    address: str = Field(description="The address of the sender of the POST message")
    ref: Optional[Union[str, ChainRef]] = Field(description="Other message referenced by this one")


class PostsResponse(PaginationResponse):
    """Response from an Aleph node API on the path /api/v0/posts.json"""

    posts: List[Post]
    pagination_item = "posts"
