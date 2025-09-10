from unittest.mock import patch

import pytest

from aleph.sdk.query.responses import AddressCreditResponse, CreditsHistoryResponse
from tests.unit.conftest import make_mock_get_session


@pytest.mark.asyncio
async def test_get_credits_history():
    """
    Test credits history commands
    """
    address = "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B24d"

    # Mock data for credit history
    credit_history_data = {
        "address": address,
        "credit_balances": [
            {
                "amount": 1000,
                "ratio": 1.0,
                "tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "token": "ALEPH",
                "chain": "ETH",
                "provider": "gateway",
                "origin": "purchase",
                "origin_ref": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "payment_method": "token",
                "credit_ref": "init_credit_1",
                "credit_index": 1,
                "expiration_date": "2025-12-31T23:59:59Z",
                "message_timestamp": "2023-01-01T12:00:00Z",
            },
            {
                "amount": -100,
                "ratio": None,
                "tx_hash": None,
                "token": None,
                "chain": None,
                "provider": "node1.aleph.im",
                "origin": "vm_usage",
                "origin_ref": "vm_instance_123456",
                "payment_method": None,
                "credit_ref": "vm_consumption_1",
                "credit_index": 2,
                "expiration_date": None,
                "message_timestamp": "2023-01-15T14:30:00Z",
            },
            {
                "amount": 500,
                "ratio": 0.8,
                "tx_hash": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
                "token": "ALEPH",
                "chain": "ETH",
                "provider": "gateway",
                "origin": "purchase",
                "origin_ref": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                "payment_method": "token",
                "credit_ref": "add_credit_1",
                "credit_index": 3,
                "expiration_date": "2026-06-30T23:59:59Z",
                "message_timestamp": "2023-02-01T09:15:00Z",
            },
        ],
        "pagination_page": 1,
        "pagination_total": 1,
        "pagination_per_page": 200,
        "pagination_item": "credit_history",
    }

    mock_client = make_mock_get_session(credit_history_data)

    # Test the method with a specific address
    expected_url = f"/api/v0/addresses/{address}/credit_history"
    # Adding type assertion to handle None case
    assert mock_client._http_session is not None
    with patch.object(
        mock_client._http_session, "get", wraps=mock_client._http_session.get
    ) as spy:
        async with mock_client:
            response = await mock_client.get_credit_history(address)

            # Verify the response
            assert isinstance(response, CreditsHistoryResponse)
            # Verify the credits history commands call the correct url
            spy.assert_called_once_with(
                expected_url, params={"page": "1", "pagination": "200"}
            )
            assert len(response.credit_balances) == 3


@pytest.mark.asyncio
async def test_get_credit_balance():
    """
    Test that the get_credit_balance method returns the correct AddressCreditResponse
    for a specific address when called on the AlephHttpClient.
    """
    address = "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B24d"

    # Mock data from the example
    credit_balance_data = {
        "address": address,
        "credits": 1000,
    }

    mock_client = make_mock_get_session(credit_balance_data)

    # Test the method with a specific address
    expected_url = f"/api/v0/addresses/{address}/credit_balance"
    # Adding type assertion to handle None case
    assert mock_client._http_session is not None
    with patch.object(
        mock_client._http_session, "get", wraps=mock_client._http_session.get
    ) as spy:
        async with mock_client:
            response = await mock_client.get_credit_balance(address)

            # Verify the response
            assert isinstance(response, AddressCreditResponse)
            # Verify the credits commands call the good url
            spy.assert_called_once_with(expected_url)

            # Those 2 assert isn't that usefull since we mocked the data, still ensure no wrong conversion is made on credits
            assert response.address == credit_balance_data["address"]
            assert response.credits == credit_balance_data["credits"]
