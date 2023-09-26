from __future__ import annotations

import logging

from aleph.sdk.query.engines.base import QueryEngine
from aleph.sdk.query.filter import MessageFilter
from aleph.sdk.query.queryset import QuerySet

logger = logging.getLogger(__name__)


class QueryManager:
    """Query manager for Aleph messages.

    This is the main entry point for querying messages from an engine with a filter.
    """

    query_filter: MessageFilter
    engine: QueryEngine
    ignore_invalid_messages: bool
    invalid_messages_log_level: int

    def __init__(
        self,
        engine: QueryEngine,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ):
        self.engine = engine
        self.ignore_invalid_messages = ignore_invalid_messages
        self.invalid_messages_log_level = invalid_messages_log_level

    def filter(self, **kwargs) -> QuerySet:
        query_filter = MessageFilter(**kwargs)
        return QuerySet(
            query_filter=query_filter,
            engine=self.engine,
            ignore_invalid_messages=self.ignore_invalid_messages,
            invalid_messages_log_level=self.invalid_messages_log_level,
        )

    def apply_filter(self, query_filter: MessageFilter) -> QuerySet:
        return QuerySet(
            query_filter=query_filter,
            engine=self.engine,
            ignore_invalid_messages=self.ignore_invalid_messages,
            invalid_messages_log_level=self.invalid_messages_log_level,
        )

    def all(self) -> QuerySet:
        """
        Return all messages. Use with caution, as this may return a lot of messages.
        """
        return QuerySet(
            query_filter=MessageFilter(),  # An empty filter should return all messages.
            engine=self.engine,
            ignore_invalid_messages=self.ignore_invalid_messages,
            invalid_messages_log_level=self.invalid_messages_log_level,
        )
