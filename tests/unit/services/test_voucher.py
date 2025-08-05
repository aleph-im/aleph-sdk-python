from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph_message.models import Chain

from aleph.sdk.client.services.voucher import Vouchers

from ..conftest import (
    MOCK_ADDRESS,
    MOCK_METADATA,
    MOCK_SOLANA_ADDRESS,
    MOCK_SOLANA_REGISTRY,
    MOCK_VOUCHER_ID,
)


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
