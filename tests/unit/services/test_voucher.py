from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph_message.models import Chain

from aleph.sdk.client.services.voucher import Vouchers

MOCK_ADDRESS = "0x1234567890123456789012345678901234567890"
MOCK_SOLANA_ADDRESS = "abcdefghijklmnopqrstuvwxyz123456789"

MOCK_METADATA_ID = "metadata123"
MOCK_VOUCHER_ID = "voucher123"
MOCK_METADATA = {
    "name": "Test Voucher",
    "description": "A test voucher",
    "external_url": "https://example.com",
    "image": "https://example.com/image.png",
    "icon": "https://example.com/icon.png",
    "attributes": [
        {"trait_type": "Test Trait", "value": "Test Value"},
        {"trait_type": "Numeric Trait", "value": "123", "display_type": "number"},
    ],
}

MOCK_EVM_VOUCHER_DATA = [
    (MOCK_VOUCHER_ID, {"claimer": MOCK_ADDRESS, "metadata_id": MOCK_METADATA_ID})
]

MOCK_SOLANA_REGISTRY = {
    "claimed_tickets": {
        "solticket123": {"claimer": MOCK_SOLANA_ADDRESS, "batch_id": "batch123"}
    },
    "batches": {"batch123": {"metadata_id": MOCK_METADATA_ID}},
}


@pytest.fixture
def make_mock_aiohttp_session():
    def _make(mocked_json_response):
        mock_response = AsyncMock()
        mock_response.json.return_value = mocked_json_response
        mock_response.raise_for_status.return_value = None

        session = MagicMock()

        get_cm = AsyncMock()
        get_cm.__aenter__.return_value = mock_response
        session.get.return_value = get_cm

        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = session
        return session_cm

    return _make


@pytest.fixture
def mock_post_response():
    mock_post = MagicMock()
    mock_post.content = {
        "nft_vouchers": {
            MOCK_VOUCHER_ID: {"claimer": MOCK_ADDRESS, "metadata_id": MOCK_METADATA_ID}
        }
    }
    posts_response = MagicMock()
    posts_response.posts = [mock_post]
    return posts_response


@pytest.mark.asyncio
async def test_get_evm_vouchers(mock_post_response, make_mock_aiohttp_session):
    mock_client = MagicMock()
    mock_client.get_posts = AsyncMock(return_value=mock_post_response)
    voucher_service = Vouchers(client=mock_client)

    session = make_mock_aiohttp_session(MOCK_METADATA)

    with patch("aiohttp.ClientSession", return_value=session):
        vouchers = await voucher_service.get_evm_vouchers(MOCK_ADDRESS)

    assert len(vouchers) == 1
    assert vouchers[0].id == MOCK_VOUCHER_ID
    assert vouchers[0].name == MOCK_METADATA["name"]


@pytest.mark.asyncio
async def test_get_solana_vouchers(make_mock_aiohttp_session):
    mock_client = MagicMock()
    voucher_service = Vouchers(client=mock_client)

    registry_session = make_mock_aiohttp_session(MOCK_SOLANA_REGISTRY)
    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)

    with patch(
        "aiohttp.ClientSession", side_effect=[registry_session, metadata_session]
    ):
        vouchers = await voucher_service.get_solana_vouchers(MOCK_SOLANA_ADDRESS)

    assert len(vouchers) == 1
    assert vouchers[0].id == "solticket123"
    assert vouchers[0].name == MOCK_METADATA["name"]


@pytest.mark.asyncio
async def test_fetch_vouchers_by_chain_for_evm(
    mock_post_response, make_mock_aiohttp_session
):
    mock_client = MagicMock()
    mock_client.get_posts = AsyncMock(return_value=mock_post_response)
    voucher_service = Vouchers(client=mock_client)

    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)
    with patch("aiohttp.ClientSession", return_value=metadata_session):
        vouchers = await voucher_service.fetch_vouchers_by_chain(
            Chain.ETH, MOCK_ADDRESS
        )

    assert len(vouchers) == 1
    assert vouchers[0].id == "voucher123"


@pytest.mark.asyncio
async def test_fetch_vouchers_by_chain_for_solana(make_mock_aiohttp_session):
    mock_client = MagicMock()
    voucher_service = Vouchers(client=mock_client)

    registry_session = make_mock_aiohttp_session(MOCK_SOLANA_REGISTRY)
    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)

    with patch(
        "aiohttp.ClientSession", side_effect=[registry_session, metadata_session]
    ):
        vouchers = await voucher_service.fetch_vouchers_by_chain(
            Chain.SOL, MOCK_SOLANA_ADDRESS
        )

    assert len(vouchers) == 1
    assert vouchers[0].id == "solticket123"


@pytest.mark.asyncio
async def test_get_vouchers_detects_chain(
    make_mock_aiohttp_session, mock_post_response
):
    mock_client = MagicMock()
    mock_client.get_posts = AsyncMock(return_value=mock_post_response)
    voucher_service = Vouchers(client=mock_client)

    # EVM
    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)
    with patch("aiohttp.ClientSession", return_value=metadata_session):
        vouchers = await voucher_service.get_vouchers(MOCK_ADDRESS)
        assert len(vouchers) == 1
        assert vouchers[0].id == "voucher123"

    # Solana
    registry_session = make_mock_aiohttp_session(MOCK_SOLANA_REGISTRY)
    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)

    with patch(
        "aiohttp.ClientSession", side_effect=[registry_session, metadata_session]
    ):
        vouchers = await voucher_service.get_vouchers(MOCK_SOLANA_ADDRESS)
        assert len(vouchers) == 1
        assert vouchers[0].id == "solticket123"
