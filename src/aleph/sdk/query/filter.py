from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional, Union

from aleph_message.models import MessageType


@dataclass
class BaseFilter:
    refs: Optional[Iterable[str]] = None
    addresses: Optional[Iterable[str]] = None
    tags: Optional[Iterable[str]] = None
    hashes: Optional[Iterable[str]] = None
    channels: Optional[Iterable[str]] = None
    chains: Optional[Iterable[str]] = None
    start_date: Optional[Union[datetime, float]] = None
    end_date: Optional[Union[datetime, float]] = None


class WatchFilter(BaseFilter):
    message_type: Optional[MessageType] = None


class MessageFilter(BaseFilter):
    """
    A collection of filters that can be applied on message queries.

    :param message_type: Filter by message type, can be "AGGREGATE", "POST", "PROGRAM", "VM", "STORE" or "FORGET"
    :param content_types: Filter by content type
    :param content_keys: Filter by content key
    :param refs: If set, only fetch posts that reference these hashes (in the "refs" field)
    :param addresses: Addresses of the posts to fetch (Default: all addresses)
    :param tags: Tags of the posts to fetch (Default: all tags)
    :param hashes: Specific item_hashes to fetch
    :param channels: Channels of the posts to fetch (Default: all channels)
    :param chains: Filter by sender address chain
    :param start_date: Earliest date to fetch messages from
    :param end_date: Latest date to fetch messages from
    """

    message_type: Optional[MessageType] = None
    content_types: Optional[Iterable[str]] = None
    content_keys: Optional[Iterable[str]] = None


class PostFilter(BaseFilter):
    types: Optional[Iterable[str]] = None
