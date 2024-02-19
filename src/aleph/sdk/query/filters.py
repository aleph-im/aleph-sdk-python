from datetime import datetime
from enum import Enum
from typing import Dict, Iterable, Optional, Union

from aleph_message.models import MessageType

from ..utils import _date_field_to_timestamp, enum_as_str, serialize_list


class SortBy(str, Enum):
    """Supported SortBy types"""

    TIME = "time"
    TX_TIME = "tx-time"


class SortOrder(str, Enum):
    """Supported SortOrder types"""

    ASCENDING = "1"
    DESCENDING = "-1"


class MessageFilter:
    """
    A collection of filters that can be applied on message queries.
    :param message_types: Filter by message type
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
    :param sort_by: Sort by time or tx-time
    :param sort_order: Sort by ascending or descending order
    """

    message_types: Optional[Iterable[MessageType]]
    content_types: Optional[Iterable[str]]
    content_keys: Optional[Iterable[str]]
    refs: Optional[Iterable[str]]
    addresses: Optional[Iterable[str]]
    tags: Optional[Iterable[str]]
    hashes: Optional[Iterable[str]]
    channels: Optional[Iterable[str]]
    chains: Optional[Iterable[str]]
    start_date: Optional[Union[datetime, float]]
    end_date: Optional[Union[datetime, float]]
    sort_by: Optional[SortBy]
    sort_order: Optional[SortOrder]

    def __init__(
        self,
        message_types: Optional[Iterable[MessageType]] = None,
        content_types: Optional[Iterable[str]] = None,
        content_keys: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
        sort_by: Optional[SortBy] = None,
        sort_order: Optional[SortOrder] = None,
    ):
        self.message_types = message_types
        self.content_types = content_types
        self.content_keys = content_keys
        self.refs = refs
        self.addresses = addresses
        self.tags = tags
        self.hashes = hashes
        self.channels = channels
        self.chains = chains
        self.start_date = start_date
        self.end_date = end_date
        self.sort_by = sort_by
        self.sort_order = sort_order

    def as_http_params(self) -> Dict[str, str]:
        """Convert the filters into a dict that can be used by an `aiohttp` client
        as `params` to build the HTTP query string.
        """

        partial_result = {
            "msgTypes": serialize_list(
                [type.value for type in self.message_types]
                if self.message_types
                else None
            ),
            "contentTypes": serialize_list(self.content_types),
            "contentKeys": serialize_list(self.content_keys),
            "refs": serialize_list(self.refs),
            "addresses": serialize_list(self.addresses),
            "tags": serialize_list(self.tags),
            "hashes": serialize_list(self.hashes),
            "channels": serialize_list(self.channels),
            "chains": serialize_list(self.chains),
            "startDate": _date_field_to_timestamp(self.start_date),
            "endDate": _date_field_to_timestamp(self.end_date),
            "sortBy": enum_as_str(self.sort_by),
            "sortOrder": enum_as_str(self.sort_order),
        }

        # Ensure all values are strings.
        result: Dict[str, str] = {}

        # Drop empty values
        for key, value in partial_result.items():
            if value:
                assert isinstance(value, str), f"Value must be a string: `{value}`"
                result[key] = value

        return result


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
    sort_by: Optional[SortBy]
    sort_order: Optional[SortOrder]

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
        sort_by: Optional[SortBy] = None,
        sort_order: Optional[SortOrder] = None,
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
        self.sort_by = sort_by
        self.sort_order = sort_order

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
            "startDate": _date_field_to_timestamp(self.start_date),
            "endDate": _date_field_to_timestamp(self.end_date),
            "sortBy": enum_as_str(self.sort_by),
            "sortOrder": enum_as_str(self.sort_order),
        }

        # Ensure all values are strings.
        result: Dict[str, str] = {}

        # Drop empty values
        for key, value in partial_result.items():
            if value:
                assert isinstance(value, str), f"Value must be a string: `{value}`"
                result[key] = value

        return result
