import unittest
from datetime import datetime

import pytest
from aleph_message.models import MessagesResponse, MessageType

from aleph.sdk.exceptions import ForgottenMessageError
from aleph.sdk.query.filters import (
    AddressesFilter,
    MessageFilter,
    PostFilter,
    SortByMessageType,
    SortOrder,
)
from aleph.sdk.query.responses import AddressStatsResponse, PostsResponse
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
async def test_get_aggregate():
    mock_session = make_mock_get_session(
        {"data": {"corechannel": {"nodes": [], "resource_nodes": []}}}
    )
    async with mock_session:
        response = await mock_session.get_aggregate(
            address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10",
            key="corechannel",
        )
    assert response is not None
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
async def test_get_aggregates():
    mock_session = make_mock_get_session(
        {"data": {"corechannel": {"nodes": [], "resource_nodes": []}}}
    )

    async with mock_session:
        response = await mock_session.get_aggregates(
            address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10"
        )
        assert response is not None
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


@pytest.mark.asyncio
async def test_get_message_error(rejected_message):
    mock_session = make_mock_get_session(rejected_message)
    async with mock_session as session:
        error = await session.get_message_error(rejected_message["item_hash"])
        assert error
        assert error["error_code"] == rejected_message["error_code"]
        assert error["details"] == rejected_message["details"]


@pytest.mark.asyncio
async def test_get_address_stats(raw_address_stats_response, address_stats_data):
    mock_session = make_mock_get_session(raw_address_stats_response(1))
    async with mock_session as session:
        response: AddressStatsResponse = await session.get_address_stats(
            page_size=20,
            page=1,
            filter=AddressesFilter(
                address_contains="0xa1",
                sort_by=SortByMessageType.TOTAL,
                sort_order=SortOrder.DESCENDING,
            ),
        )

        address_stats = response.data
        assert len(address_stats) == 2

        # Get the first address from the stats data
        first_address = address_stats_data[0]["address"]
        assert first_address in address_stats
        assert address_stats[first_address].messages == address_stats_data[0]["total"]
        assert address_stats[first_address].post == address_stats_data[0]["post"]
        assert (
            address_stats[first_address].aggregate == address_stats_data[0]["aggregate"]
        )
        assert address_stats[first_address].store == address_stats_data[0]["store"]
        assert address_stats[first_address].forget == address_stats_data[0]["forget"]
        assert address_stats[first_address].program == address_stats_data[0]["program"]
        assert (
            address_stats[first_address].instance == address_stats_data[0]["instance"]
        )


@pytest.mark.asyncio
async def test_get_address_stats_without_filter(raw_address_stats_response):
    mock_session = make_mock_get_session(raw_address_stats_response(1))
    async with mock_session as session:
        response: AddressStatsResponse = await session.get_address_stats(
            page_size=20,
            page=1,
        )

        address_stats = response.data
        assert len(address_stats) == 2
        assert response.pagination_page == 1
        assert response.pagination_item == "addresses"


if __name__ == "__main __":
    unittest.main()
