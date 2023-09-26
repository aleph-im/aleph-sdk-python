from __future__ import annotations

from typing import AsyncIterator

from aleph_message.models import AlephMessage

from aleph.sdk.query.engines.base import QueryEngine


class SqliteDatabase:
    # Should use Peewee or something similar
    pass


class SqliteQueryEngine(QueryEngine):
    async def page(self, page: int = 0, page_size: int = 200):
        raise NotImplementedError()

    async def __aiter__(self) -> AsyncIterator[AlephMessage]:
        raise NotImplementedError()
