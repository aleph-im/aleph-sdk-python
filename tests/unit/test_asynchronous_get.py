import unittest
from datetime import datetime

import pytest
from aleph_message.models import MessagesResponse, MessageType

from aleph.sdk.exceptions import ForgottenMessageError
from aleph.sdk.query.filters import MessageFilter, PostFilter
from aleph.sdk.query.responses import PostsResponse
from tests.unit.conftest import make_mock_get_session


@pytest.mark.asyncio
async def test_fetch_aggregate():
    mock_session = make_mock_get_session(
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
    mock_session = make_mock_get_session(
        {"data": {"corechannel": {"nodes": [], "resource_nodes": []}}}
    )

    async with mock_session:
        response = await mock_session.fetch_aggregates(
            address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10"
        )
        assert response.keys() == {"corechannel"}
        assert response["corechannel"].keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_get_posts(raw_posts_response):
    mock_session = make_mock_get_session(raw_posts_response(1))
    post = raw_posts_response(1)["posts"][0]
    async with mock_session as session:
        response: PostsResponse = await session.get_posts(
            page=1,
            page_size=1,
            post_filter=PostFilter(
                channels=post["channel"],
                start_date=datetime.fromtimestamp(post["time"]),
            ),
            ignore_invalid_messages=False,
        )

        posts = response.posts
        assert len(posts) == 1


@pytest.mark.asyncio
async def test_get_messages(raw_messages_response):
    mock_session = make_mock_get_session(raw_messages_response(1))
    async with mock_session as session:
        response: MessagesResponse = await session.get_messages(
            page_size=2,
            message_filter=MessageFilter(
                message_types=[MessageType.post],
                start_date=datetime(2021, 1, 1),
            ),
            ignore_invalid_messages=False,
        )

        messages = response.messages
        assert len(messages) >= 1
        assert messages[0].type
        assert messages[0].sender


@pytest.mark.asyncio
async def test_get_forgotten_message():
    mock_session = make_mock_get_session(
        {"status": "forgotten", "item_hash": "cafebabe", "forgotten_by": "OxBEEFDAD"}
    )
    async with mock_session as session:
        with pytest.raises(ForgottenMessageError):
            await session.get_message("cafebabe")


if __name__ == "__main __":
    unittest.main()
