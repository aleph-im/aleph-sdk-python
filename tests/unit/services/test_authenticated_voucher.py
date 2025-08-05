from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.sdk.client.services.authenticated_voucher import AuthenticatedVoucher

from ..conftest import (
    MOCK_ADDRESS,
    MOCK_METADATA,
    MOCK_SOLANA_ADDRESS,
    MOCK_SOLANA_REGISTRY,
    MOCK_VOUCHER_ID,
)


def test_resolve_address_with_argument():
    client = MagicMock()
    service = AuthenticatedVoucher(client=client)
    assert service._resolve_address(address="custom-address") == "custom-address"


def test_resolve_address_with_account_fallback():
    mock_account = MagicMock()
    mock_account.get_address.return_value = MOCK_ADDRESS

    client = MagicMock()
    client.account = mock_account

    service = AuthenticatedVoucher(client=client)
    assert service._resolve_address(address=None) == MOCK_ADDRESS
    mock_account.get_address.assert_called_once()


def test_resolve_address_no_address_no_account():
    client = MagicMock()
    client.account = None

    service = AuthenticatedVoucher(client=client)

    with pytest.raises(
        ValueError, match="No address provided and no account configured"
    ):
        service._resolve_address(address=None)


@pytest.mark.asyncio
async def test_get_vouchers_fallback_to_account(
    make_mock_aiohttp_session, mock_post_response
):
    mock_account = MagicMock()
    mock_account.get_address.return_value = MOCK_ADDRESS

    mock_client = MagicMock()
    mock_client.account = mock_account
    mock_client.get_posts = AsyncMock(return_value=mock_post_response)

    service = AuthenticatedVoucher(client=mock_client)

    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)

    with patch("aiohttp.ClientSession", return_value=metadata_session):
        vouchers = await service.get_vouchers()

    assert len(vouchers) == 1
    assert vouchers[0].name == MOCK_METADATA["name"]
    mock_account.get_address.assert_called_once()


@pytest.mark.asyncio
async def test_get_evm_vouchers_fallback_to_account(
    make_mock_aiohttp_session, mock_post_response
):
    mock_account = MagicMock()
    mock_account.get_address.return_value = MOCK_ADDRESS

    mock_client = MagicMock()
    mock_client.account = mock_account
    mock_client.get_posts = AsyncMock(return_value=mock_post_response)

    service = AuthenticatedVoucher(client=mock_client)

    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)

    with patch("aiohttp.ClientSession", return_value=metadata_session):
        vouchers = await service.get_evm_vouchers()

    assert len(vouchers) == 1
    assert vouchers[0].id == MOCK_VOUCHER_ID


@pytest.mark.asyncio
async def test_get_solana_vouchers_fallback_to_account(make_mock_aiohttp_session):
    mock_account = MagicMock()
    mock_account.get_address.return_value = MOCK_SOLANA_ADDRESS

    mock_client = MagicMock()
    mock_client.account = mock_account

    service = AuthenticatedVoucher(client=mock_client)

    registry_session = make_mock_aiohttp_session(MOCK_SOLANA_REGISTRY)
    metadata_session = make_mock_aiohttp_session(MOCK_METADATA)

    with patch(
        "aiohttp.ClientSession", side_effect=[registry_session, metadata_session]
    ):
        vouchers = await service.get_solana_vouchers()

    assert len(vouchers) == 1
    assert vouchers[0].id == "solticket123"
    assert vouchers[0].name == MOCK_METADATA["name"]
