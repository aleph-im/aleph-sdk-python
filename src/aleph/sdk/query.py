from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Union

import aiohttp
from aleph_message.models import (
    AlephMessage,
    MessagesResponse,
    MessageType,
    parse_message,
)
from pydantic import ValidationError

logger = logging.getLogger(__name__)


def serialize_list(values: Optional[Iterable[str]]) -> Optional[str]:
    if values:
        return ",".join(values)
    else:
        return None


def _date_field_to_float(date: Optional[Union[datetime, float]]) -> Optional[float]:
    if date is None:
        return None
    elif isinstance(date, float):
        return date
    elif hasattr(date, "timestamp"):
        return date.timestamp()
    else:
        raise TypeError(f"Invalid type: `{type(date)}`")


class MessageQueryFilter:
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

    message_type: Optional[MessageType]
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

    def __init__(
        self,
        message_type: Optional[MessageType] = None,
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
    ):
        self.message_type = message_type
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

    def as_http_params(self) -> Dict[str, str]:
        """Convert the filters into a dict that can be used by an `aiohttp` client
        as `params` to build the HTTP query string.
        """

        partial_result = {
            "msgType": self.message_type.value if self.message_type else None,
            "contentTypes": serialize_list(self.content_types),
            "contentKeys": serialize_list(self.content_keys),
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


class MessageQuery:
    """
    Interface to query messages from an API server.

    :param query_filter: The filter to apply when fetching messages
    :param http_client_session: The Aiohttp client session to the API server
    :param ignore_invalid_messages: Ignore invalid messages (Default: False)
    :param invalid_messages_log_level: Log level to use for invalid messages (Default: logging.NOTSET)
    """

    query_filter: MessageQueryFilter
    http_client_session: aiohttp.ClientSession
    ignore_invalid_messages: bool
    invalid_messages_log_level: int

    def __init__(
        self,
        query_filter: MessageQueryFilter,
        http_client_session: aiohttp.ClientSession,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ):
        self.query_filter = query_filter
        self.http_client_session = http_client_session
        self.ignore_invalid_messages = ignore_invalid_messages
        self.invalid_messages_log_level = invalid_messages_log_level

    async def fetch_json(self, page: int = 0, pagination: int = 200):
        """Return the raw JSON response from the API server."""
        params: Dict[str, Any] = self.query_filter.as_http_params()
        params["page"] = str(page)
        params["pagination"] = str(pagination)
        async with self.http_client_session.get(
            "/api/v0/messages.json", params=params
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def fetch(self, page: int = 0, pagination: int = 200):
        """Return the parsed messages from the API server."""
        response_json = await self.fetch_json(page=page, pagination=pagination)

        messages_raw = response_json["messages"]

        # All messages may not be valid according to the latest specification in
        # aleph-message. This allows the user to specify how errors should be handled.
        messages: List[AlephMessage] = []
        for message_raw in messages_raw:
            try:
                message = parse_message(message_raw)
                messages.append(message)
            except KeyError as e:
                if not self.ignore_invalid_messages:
                    raise e
                logger.log(
                    level=self.invalid_messages_log_level,
                    msg=f"KeyError: Field '{e.args[0]}' not found",
                )
            except ValidationError as e:
                if not self.ignore_invalid_messages:
                    raise e
                if self.invalid_messages_log_level:
                    logger.log(level=self.invalid_messages_log_level, msg=e)

        return MessagesResponse(
            messages=messages,
            pagination_page=response_json["pagination_page"],
            pagination_total=response_json["pagination_total"],
            pagination_per_page=response_json["pagination_per_page"],
            pagination_item=response_json["pagination_item"],
        )

    async def __aiter__(self) -> AsyncIterator[AlephMessage]:
        """Iterate asynchronously over matching messages.
        Handles pagination internally.

        ```
        async for message in MessageQuery(query_filter=filter):
            print(message)
        ```
        """
        page: int = 0
        partial_result = await self.fetch(page=0)
        while partial_result:
            for message in partial_result.messages:
                yield message

            page += 1
            partial_result = await self.fetch(page=0)
