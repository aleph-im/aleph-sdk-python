import unittest
from typing import Any, Dict
from unittest.mock import AsyncMock

import pytest
from aleph_message.models import MessagesResponse, MessageType

from aleph.sdk.client import AlephClient
from aleph.sdk.conf import settings


def make_mock_session(get_return_value: Dict[str, Any]) -> AlephClient:
    class MockResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            ...

        @property
        def status(self):
            return 200

        async def json(self):
            return get_return_value

    class MockHttpSession(AsyncMock):
        def get(self, *_args, **_kwargs):
            return MockResponse()

    http_session = MockHttpSession()

    client = AlephClient(api_server="http://localhost")
    client.http_session = http_session

    return client


@pytest.mark.asyncio
async def test_fetch_aggregate():
    mock_session = make_mock_session(
        {"data": {"corechannel": {"nodes": [], "resource_nodes": []}}}
    )
    async with mock_session:
        response = await mock_session.fetch_aggregate(
            address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10",
            key="corechannel",
        )
    assert response.keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_fetch_aggregates():
    mock_session = make_mock_session(
        {"data": {"corechannel": {"nodes": [], "resource_nodes": []}}}
    )

    async with mock_session:
        response = await mock_session.fetch_aggregates(
            address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10"
        )
        assert response.keys() == {"corechannel"}
        assert response["corechannel"].keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_get_posts():
    async with AlephClient(api_server=settings.API_HOST) as session:
        response: MessagesResponse = await session.get_messages(
            message_type=MessageType.post,
        )

        messages = response.messages
        assert len(messages) > 1
        for message in messages:
            assert message.type == MessageType.post


@pytest.mark.asyncio
async def test_get_messages():
    async with AlephClient(api_server=settings.API_HOST) as session:
        response: MessagesResponse = await session.get_messages(
            pagination=2,
        )

        messages = response.messages
        assert len(messages) > 1
        assert messages[0].type
        assert messages[0].sender


if __name__ == "__main __":
    unittest.main()
