from unittest.mock import patch

import pytest

from aleph.sdk.query.responses import CreditsHistoryResponse
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
        "credit_history": [
            {
                "amount": -22,
                "ratio": None,
                "tx_hash": None,
                "token": None,
                "chain": None,
                "provider": "ALEPH",
                "origin": None,
                "origin_ref": "212f4825dd30e01f3801cdff1bdf8cd4d1c14ce2d31d695aee429d2ad0dfcba1",
                "payment_method": "credit_expense",
                "credit_ref": "cd77a7983af168941fd011427c6198b146ccd6f85077e0b593a4e7239d45fb11",
                "credit_index": 0,
                "expiration_date": None,
                "message_timestamp": "2025-09-30T06:57:26.106000Z",
            },
            {
                "amount": -22,
                "ratio": None,
                "tx_hash": None,
                "token": None,
                "chain": None,
                "provider": "ALEPH",
                "origin": None,
                "origin_ref": "36ceb85fb570fc87a6b906dc89df39129a971de96cbc56250553cfb8d49487e3",
                "payment_method": "credit_expense",
                "credit_ref": "5881c8f813ea186b25a9a20d9bea46e2082c4d61c2b9e7d53bf8a164dc892b73",
                "credit_index": 0,
                "expiration_date": None,
                "message_timestamp": "2025-09-30T02:57:07.673000Z",
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
            assert len(response.credit_history) == 2
