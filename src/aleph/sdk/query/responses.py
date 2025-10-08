from __future__ import annotations

import datetime as dt
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union

from aleph_message.models import (
    AlephMessage,
    Chain,
    ItemHash,
    ItemType,
    MessageConfirmation,
)
from pydantic import BaseModel, ConfigDict, Field


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
    address: Optional[str] = Field(description="Address of the sender")

    model_config = ConfigDict(extra="forbid")


class PaginationResponse(BaseModel):
    pagination_page: int
    pagination_total: int
    pagination_per_page: int
    pagination_item: str


class PostsResponse(PaginationResponse):
    """Response from an aleph.im node API on the path /api/v0/posts.json"""

    posts: List[Post]
    pagination_item: str = "posts"


class MessagesResponse(PaginationResponse):
    """Response from an aleph.im node API on the path /api/v0/messages.json"""

    messages: List[AlephMessage]
    pagination_item: str = "messages"


class PriceResponse(BaseModel):
    """Response from an aleph.im node API on the path /api/v0/price/{item_hash}"""

    required_tokens: Decimal
    cost: Optional[str] = None
    payment_type: str


class CreditsHistoryResponse(PaginationResponse):
    """Response from an aleph.im node API on the path /api/v0/credits"""

    address: str
    credit_history: List[CreditHistoryResponseItem]
    pagination_item: str = "credit_history"


class CreditHistoryResponseItem(BaseModel):
    amount: int
    ratio: Optional[Decimal] = None
    tx_hash: Optional[str] = None
    token: Optional[str] = None
    chain: Optional[str] = None
    provider: Optional[str] = None
    origin: Optional[str] = None
    origin_ref: Optional[str] = None
    payment_method: Optional[str] = None
    credit_ref: str
    credit_index: int
    expiration_date: Optional[dt.datetime] = None
    message_timestamp: dt.datetime


class BalanceResponse(BaseModel):
    address: str
    balance: Decimal
    details: Optional[Dict[str, Decimal]] = None
    locked_amount: Decimal
    credit_balance: int = 0
