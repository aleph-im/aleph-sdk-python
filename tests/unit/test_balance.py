from unittest.mock import patch

import pytest

from aleph.sdk.query.responses import BalanceResponse
from tests.unit.conftest import make_mock_get_session


@pytest.mark.asyncio
async def test_get_balances():
    """
    Test that the get_balances method returns the correct BalanceResponse
    for a specific address when called on the AlephHttpClient.
    """
    address = "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B24d"

    balance_data = {
        "address": address,
        "balance": 351.25,
        "details": {"ETH": 100.5, "SOL": 250.75},
        "locked_amount": 50.0,
        "credit_balance": 1000,
    }

    mock_client = make_mock_get_session(balance_data)

    expected_url = f"/api/v0/addresses/{address}/balance"
    # Adding type assertion to handle None case
    assert mock_client._http_session is not None
    with patch.object(
        mock_client._http_session, "get", wraps=mock_client._http_session.get
    ) as spy:
        async with mock_client:
            response = await mock_client.get_balances(address)

            # Verify the response
            assert isinstance(response, BalanceResponse)
            # Verify the balances command calls the correct URL
            spy.assert_called_once_with(expected_url, params=None)
