import unittest
from datetime import datetime

import pytest
from aleph_message.models import Chain, MessagesResponse, MessageType

from aleph.sdk.exceptions import ForgottenMessageError
from aleph.sdk.query.filters import (
    AccountFilesFilter,
    AddressesFilter,
    ChainBalancesFilter,
    MessageFilter,
    PostFilter,
    SortByMessageType,
    SortOrder,
)
from aleph.sdk.query.responses import (
    AccountFilesResponse,
    AddressStatsResponse,
    ChainBalancesResponse,
    PostsResponse,
)
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
async def test_list_aggregates():
    mock_session = make_mock_get_session(
        {
            "aggregates": [
                {
                    "address": "0xabc",
                    "key": "domains",
                    "content": {"example.com": {"type": "ipfs"}},
                }
            ],
            "pagination_page": 1,
            "pagination_total": 1,
            "pagination_per_page": 20,
            "pagination_item": "aggregates",
        }
    )
    async with mock_session:
        response = await mock_session.list_aggregates(keys=["domains"])
    assert response.pagination_total == 1
    assert len(response.aggregates) == 1
    assert response.aggregates[0]["key"] == "domains"


@pytest.mark.asyncio
async def test_list_aggregates_with_addresses():
    mock_session = make_mock_get_session(
        {
            "aggregates": [],
            "pagination_page": 1,
            "pagination_total": 0,
            "pagination_per_page": 20,
            "pagination_item": "aggregates",
        }
    )
    async with mock_session:
        response = await mock_session.list_aggregates(
            keys=["domains"], addresses=["0xabc", "0xdef"], pagination=100
        )
    assert response.pagination_total == 0
    assert len(response.aggregates) == 0


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
        assert (
            address_stats[first_address].messages == address_stats_data[0]["messages"]
        )
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


@pytest.mark.asyncio
async def test_get_account_files(address_files_data):
    mock_session = make_mock_get_session(address_files_data)
    async with mock_session as session:
        response: AccountFilesResponse = await session.get_account_files(
            address="0xd463495a6FEaC9921FD0C3a595B81E7B2C02B24d",
            page_size=100,
            page=1,
            filter=AccountFilesFilter(sort_order=SortOrder.DESCENDING),
        )

        files = response.files
        assert len(files) >= 1
        assert response.address
        assert response.total_size >= 0
        assert response.pagination_item == "files"


@pytest.mark.asyncio
async def test_get_account_files_without_filter():
    address = "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B24d"
    files_data = {
        "address": address,
        "total_size": 1024000,
        "files": [
            {
                "file_hash": "QmTest",
                "size": 1024000,
                "type": "file",
                "created": "2024-01-15T10:30:00",
                "item_hash": "testitem",
            }
        ],
        "pagination_page": 1,
        "pagination_total": 1,
        "pagination_per_page": 100,
        "pagination_item": "files",
    }

    mock_session = make_mock_get_session(files_data)
    async with mock_session as session:
        response: AccountFilesResponse = await session.get_account_files(
            address=address,
            page_size=100,
            page=1,
        )

        assert len(response.files) == 1
        assert response.pagination_page == 1
        assert response.pagination_item == "files"


@pytest.mark.asyncio
async def test_get_chain_balances(raw_chain_balances_response, chain_balances_data):
    """Test the get_chain_balances endpoint with filters applied."""
    mock_session = make_mock_get_session(raw_chain_balances_response(1))
    async with mock_session as session:
        response: ChainBalancesResponse = await session.get_chain_balances(
            page_size=100,
            page=1,
            filter=ChainBalancesFilter(
                chains=[Chain.ETH, Chain.AVAX],
                min_balance=100,
            ),
        )

        balances = response.balances
        assert len(balances) == 3
        assert balances[0].address == chain_balances_data[0]["address"]
        assert float(balances[0].balance) == chain_balances_data[0]["balance"]
        assert balances[0].chain == Chain.ETH
        assert response.pagination_item == "balances"
        assert response.pagination_page == 1
        assert response.pagination_total == 3


@pytest.mark.asyncio
async def test_get_chain_balances_without_filter(raw_chain_balances_response):
    """Test the get_chain_balances endpoint without filters."""
    mock_session = make_mock_get_session(raw_chain_balances_response(1))
    async with mock_session as session:
        response: ChainBalancesResponse = await session.get_chain_balances(
            page_size=100,
            page=1,
        )

        assert len(response.balances) >= 0
        assert response.pagination_page == 1
        assert response.pagination_item == "balances"


def test_addresses_filter_as_http_params():
    f = AddressesFilter(
        address_contains="0xabc",
        sort_by=SortByMessageType.TOTAL,
        sort_order=SortOrder.DESCENDING,
    )
    params = f.as_http_params()
    assert params == {
        "addressContains": "0xabc",
        "sortBy": "total",
        "sortOrder": "-1",
    }


def test_addresses_filter_drops_none_values():
    assert AddressesFilter().as_http_params() == {}
    assert AddressesFilter(address_contains="x").as_http_params() == {
        "addressContains": "x"
    }


def test_account_files_filter_uses_camel_case():
    f = AccountFilesFilter(sort_order=SortOrder.ASCENDING)
    params = f.as_http_params()
    assert params == {"sortOrder": "1"}


def test_chain_balances_filter_as_http_params():
    f = ChainBalancesFilter(chains=[Chain.ETH, Chain.AVAX], min_balance=10)
    params = f.as_http_params()
    assert params == {"chains": "ETH,AVAX", "minBalance": "10"}


def test_chain_balances_filter_rejects_invalid_min_balance():
    with pytest.raises(ValueError, match="min_balance must be >= 1"):
        ChainBalancesFilter(min_balance=0)
    with pytest.raises(ValueError, match="min_balance must be >= 1"):
        ChainBalancesFilter(min_balance=-5)


def test_chain_balances_filter_accepts_min_balance_one():
    f = ChainBalancesFilter(min_balance=1)
    assert f.as_http_params() == {"minBalance": "1"}


@pytest.mark.asyncio
async def test_get_account_files_rejects_path_traversal():
    """address with path separators or .. must raise ValueError before any HTTP call."""
    mock_session = make_mock_get_session({})
    async with mock_session as session:
        for bad_address in [
            "../etc/passwd",
            "./etc/passwd",
            "foo/bar",
            "a\\b",
            "..foo",
        ]:
            with pytest.raises(ValueError, match="Invalid address"):
                await session.get_account_files(address=bad_address)


@pytest.mark.asyncio
async def test_get_account_files_rejects_empty_address():
    mock_session = make_mock_get_session({})
    async with mock_session as session:
        for bad_address in ["", "   ", "\t", "\n"]:
            with pytest.raises(ValueError, match="must not be empty"):
                await session.get_account_files(address=bad_address)


if __name__ == "__main __":
    unittest.main()
