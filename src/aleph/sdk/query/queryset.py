from __future__ import annotations

import logging
from typing import AsyncIterator, List

from aleph_message.models import (
    AlephMessage,
    MessagesResponse,
    item_hash,
    parse_message,
)
from pydantic import ValidationError

from aleph.sdk.exceptions import MessageNotFoundError, MultipleMessagesError
from aleph.sdk.query.engines.base import QueryEngine
from aleph.sdk.query.filter import MessageFilter, BaseFilter

logger = logging.getLogger(__name__)


class QuerySet:
    """QuerySet for Aleph messages.

    Helps to iterate over messages from an engine with a filter.
    """

    query_filter: BaseFilter
    engine: QueryEngine
    ignore_invalid_messages: bool
    invalid_messages_log_level: int

    def __init__(
        self,
        query_filter: BaseFilter,
        engine: QueryEngine,
        ignore_invalid_messages: bool,
        invalid_messages_log_level: int,
    ):
        self.query_filter = query_filter
        self.engine = engine
        self.ignore_invalid_messages = ignore_invalid_messages
        self.invalid_messages_log_level = invalid_messages_log_level

    async def fetch_messages(
        self, page: int = 0, page_size: int = 200
    ) -> MessagesResponse:
        """Return the parsed messages from the API server."""
        response_json = await self.engine.fetch_messages(
            query_filter=self.query_filter, page=page, page_size=page_size
        )

        messages_raw = response_json["messages"]  # TODO: Depends on API response format

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
        partial_result = await self.fetch_messages(page=0)
        while partial_result:
            for message in partial_result.messages:
                yield message

            page += 1
            partial_result = await self.fetch_messages(page=0)

    async def first(self) -> AlephMessage:
        """Return the first matching message."""
        response = await self.fetch_messages(page=0, page_size=1)

        # Raise specific exceptions.
        if len(response.messages) < 1:
            raise MessageNotFoundError(f"No such hash {item_hash}")
        if len(response.messages) != 1:
            raise MultipleMessagesError(
                f"Multiple messages found for the same item_hash `{item_hash}`"
            )

        message = response.messages[0]
        return message

    def watch(self) -> AsyncIterator[AlephMessage]:
        """Watch for new messages.
        This is an infinite iterator that will yield messages as they are received.
        """
        return self.engine.watch_messages(query_filter=self.query_filter)
