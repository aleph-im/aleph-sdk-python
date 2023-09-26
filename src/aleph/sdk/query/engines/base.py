from __future__ import annotations

from typing import Any, AsyncIterator, List, Optional, Protocol, Dict

from aleph_message.models import AlephMessage

from aleph.sdk.query.filter import MessageFilter, WatchFilter


class QueryEngine(Protocol):
    """
    Interface to query messages from an API server.

    :param query_filter: The filter to apply when fetching messages
    :param http_client_session: The Aiohttp client session to the API server
    :param ignore_invalid_messages: Ignore invalid messages (Default: False)
    :param invalid_messages_log_level: Log level to use for invalid messages (Default: logging.NOTSET)
    """

    query_filter: MessageFilter
    source: Any

    def stop(self):
        pass

    async def __aiter__(self) -> AsyncIterator[AlephMessage]:
        pass

    async def first(self) -> Optional[AlephMessage]:
        pass

    async def all(self) -> List[AlephMessage]:
        pass

    async def fetch_messages(
        self, query_filter: MessageFilter, page: int = 0, page_size: int = 200
    ):
        pass

    async def fetch_aggregate(
        self,
        address: str,
        key: str,
        limit: int = 100,
    ) -> Dict[str, Dict]:
        pass

    async def watch_messages(
        self, query_filter: WatchFilter
    ) -> AsyncIterator[AlephMessage]:
        yield
        raise NotImplementedError()
