from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, AsyncIterator, Dict, Iterable, Optional, Union

import aiohttp
from aleph_message import parse_message
from aleph_message.models import AlephMessage
from yarl import URL

from aleph.sdk.conf import settings
from aleph.sdk.query.engines.base import QueryEngine
from aleph.sdk.query.filter import MessageFilter, WatchFilter, BaseFilter, PostFilter
from aleph.sdk.utils import check_unix_socket_valid

logger = logging.getLogger(__name__)


def create_http_session(
    api_server: Optional[str] = None,
    api_unix_socket: Optional[str] = None,
    allow_unix_sockets: bool = True,
    timeout: Optional[aiohttp.ClientTimeout] = None,
):
    """Create an HTTP session, using an UNIX socket or TCP and an optional timeout."""

    host = api_server or settings.API_HOST
    if not host:
        raise ValueError("Missing API host")

    unix_socket_path = api_unix_socket or settings.API_UNIX_SOCKET
    if unix_socket_path and allow_unix_sockets:
        check_unix_socket_valid(unix_socket_path)
        connector = aiohttp.UnixConnector(path=unix_socket_path)
    else:
        connector = None

    # ClientSession timeout defaults to a private sentinel object and may not be None.
    return (
        aiohttp.ClientSession(
            base_url=host,
            connector=connector,
            timeout=timeout,
        )
        if timeout
        else aiohttp.ClientSession(
            base_url=host,
            connector=connector,
        )
    )


class HttpQueryEngine(QueryEngine):
    _http_session: aiohttp.ClientSession
    _api_server: URL
    ignore_invalid_messages: bool
    invalid_messages_log_level: int

    def __init__(
        self,
        http_session: aiohttp.ClientSession,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ):
        base_url = http_session._base_url
        if not base_url:
            raise ValueError("No API server defined on the HTTP session.")

        self._http_session = http_session
        self._api_server = base_url
        self.ignore_invalid_messages = ignore_invalid_messages
        self.invalid_messages_log_level = invalid_messages_log_level

    async def stop(self):
        await self._http_session.close()

    @property
    def source(self) -> URL:
        return self._api_server

    @classmethod
    def create_with_new_session(
        cls,
        api_server: Optional[str] = None,
        api_unix_socket: Optional[str] = None,
        allow_unix_sockets: bool = True,
        timeout: Optional[aiohttp.ClientTimeout] = None,
    ) -> HttpQueryEngine:
        http_session = create_http_session(
            api_server=api_server,
            api_unix_socket=api_unix_socket,
            allow_unix_sockets=allow_unix_sockets,
            timeout=timeout,
        )
        return cls(
            http_session=http_session,
        )

    async def fetch_messages(
        self, query_filter, page: int = 0, page_size: int = 200
    ) -> Dict[str, Any]:
        """Return the raw JSON response from the API server."""
        params: Dict[str, Any] = self._convert_query_filter(query_filter)
        params["page"] = str(page)
        params["pagination"] = str(page_size)
        async with self._http_session.get(
            "/api/v0/messages.json", params=params
        ) as resp:
            resp.raise_for_status()
            result = await resp.json()
            return result

    async def fetch_aggregate(
        self,
        address: str,
        key: str,
        limit: int = 100,
    ) -> Dict[str, Dict]:
        """
        Fetch a value from the aggregate store by owner address and item key.

        :param address: Address of the owner of the aggregate
        :param key: Key of the aggregate
        :param limit: Maximum number of items to fetch (Default: 100)
        """

        params: Dict[str, Any] = {"keys": key}
        if limit:
            params["limit"] = limit

        async with self._http_session.get(
            f"/api/v0/aggregates/{address}.json", params=params
        ) as resp:
            result = await resp.json()
            data = result.get("data", dict())
            return data.get(key)

    async def fetch_aggregates(
        self,
        address: str,
        keys: Optional[Iterable[str]] = None,
        limit: int = 100,
    ) -> Dict[str, Dict]:
        """
        Fetch key-value pairs from the aggregate store by owner address.

        :param address: Address of the owner of the aggregate
        :param keys: Keys of the aggregates to fetch (Default: all items)
        :param limit: Maximum number of items to fetch (Default: 100)
        """

        keys_str = ",".join(keys) if keys else ""
        params: Dict[str, Any] = {}
        if keys_str:
            params["keys"] = keys_str
        if limit:
            params["limit"] = limit

        async with self._http_session.get(
            f"/api/v0/aggregates/{address}.json",
            params=params,
        ) as resp:
            result = await resp.json()
            data = result.get("data", dict())
            return data

    async def watch_messages(
        self, query_filter: WatchFilter
    ) -> AsyncIterator[AlephMessage]:
        """Return an async iterator that will yield messages as they are received."""
        params: Dict[str, Any] = self._convert_query_filter(query_filter)
        async with self._http_session.ws_connect(
            "/api/ws0/messages", params=params
        ) as ws:
            logger.debug("Websocket connected")
            async for msg in ws:
                msg: aiohttp.WSMessage
                if msg.type == aiohttp.WSMsgType.TEXT:
                    if msg.data == "close cmd":
                        await ws.close()
                        break
                    else:
                        data: Dict = json.loads(msg.data)
                        yield parse_message(data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break

    @staticmethod
    def _convert_query_filter(query_filter: BaseFilter) -> Dict[str, Any]:
        """Convert the filters into a dict that can be used by an `aiohttp` client
        as `params` to build the HTTP query string.
        """

        message_type = (
            query_filter.message_type.value if query_filter.message_type else None
        )

        partial_result = {
            "msgType": message_type,
            "contentTypes": serialize_list(query_filter.content_types),
            "refs": serialize_list(query_filter.refs),
            "addresses": serialize_list(query_filter.addresses),
            "tags": serialize_list(query_filter.tags),
            "hashes": serialize_list(query_filter.hashes),
            "channels": serialize_list(query_filter.channels),
            "chains": serialize_list(query_filter.chains),
            "startDate": _date_field_to_float(query_filter.start_date),
            "endDate": _date_field_to_float(query_filter.end_date),
        }

        if isinstance(query_filter, MessageFilter):
            partial_result["contentKeys"] = serialize_list(query_filter.content_keys)

        if isinstance(query_filter, PostFilter):
            partial_result["types"] = serialize_list(query_filter.types)

        # Ensure all values are strings.
        result: Dict[str, str] = {}

        # Drop empty values
        for key, value in partial_result.items():
            if value:
                assert isinstance(value, str), f"Value must be a string: `{value}`"
                result[key] = value

        return result


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
