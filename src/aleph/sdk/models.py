from typing import List

from aleph_message.models import AlephMessage, PostMessage
from pydantic import BaseModel


class PaginationResponse(BaseModel):
    pagination_page: int
    pagination_total: int
    pagination_per_page: int
    pagination_item: str


class MessagesResponse(PaginationResponse):
    """Response from an Aleph node API on the path /api/v0/messages.json"""

    messages: List[AlephMessage]
    pagination_item = "messages"


class PostsResponse(PaginationResponse):
    """Response from an Aleph node API on the path /api/v0/posts.json"""

    posts: List[PostMessage]
    pagination_item = "posts"
