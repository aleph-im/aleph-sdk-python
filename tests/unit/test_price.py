import pytest

from aleph.sdk.exceptions import InvalidHashError
from aleph.sdk.query.responses import PriceResponse
from tests.unit.conftest import make_mock_get_session, make_mock_get_session_400


@pytest.mark.asyncio
async def test_get_program_price_valid():
    """
    Test that the get_program_price method returns the correct PriceResponse
    when given a valid item hash.
    """
    expected_response = {
        "required_tokens": 3.0555555555555556e-06,
        "payment_type": "superfluid",
    }
    mock_session = make_mock_get_session(expected_response)
    async with mock_session:
        response = await mock_session.get_program_price("cacacacacacaca")
        assert response == PriceResponse(**expected_response)


@pytest.mark.asyncio
async def test_get_program_price_invalid():
    """
    Test that the get_program_price method raises an InvalidHashError
    when given an invalid item hash.
    """
    mock_session = make_mock_get_session_400({"error": "Invalid hash"})
    async with mock_session:
        with pytest.raises(InvalidHashError):
            await mock_session.get_program_price("invalid_item_hash")
