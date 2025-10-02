from decimal import Decimal

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
    expected = PriceResponse(
        required_tokens=3.0555555555555556e-06,
        payment_type="superfluid",
    )
    mock_session = make_mock_get_session(expected.model_dump())
    async with mock_session:
        response = await mock_session.get_program_price("cacacacacacaca")
        assert response == expected


@pytest.mark.asyncio
async def test_get_program_price_cost_and_required_token():
    """
    Test that the get_program_price method returns the correct PriceResponse
    when
        1 ) cost & required_token is here (priority to cost) who is a string that convert to decimal
        2 ) When only required_token is here who is a float that now would be to be convert to decimal
    """
    # Case 1
    expected = {
        "required_tokens": 0.001527777777777778,
        "cost": "0.001527777777777777",
        "payment_type": "credit",
    }

    # Case 2
    expected_old = {
        "required_tokens": 0.001527777777777778,
        "payment_type": "credit",
    }

    # Expected model using the cost field as the source of truth
    expected_model = PriceResponse(
        required_tokens=Decimal("0.001527777777777777"),
        payment_type=expected["payment_type"],
    )

    # Expected model for the old format
    expected_model_old = PriceResponse(
        required_tokens=Decimal(str(expected_old["required_tokens"])),
        payment_type=expected_old["payment_type"],
    )

    mock_session = make_mock_get_session(expected)
    mock_session_old = make_mock_get_session(expected_old)

    async with mock_session:
        response = await mock_session.get_program_price("cacacacacacaca")
        assert response == expected_model

    async with mock_session_old:
        response = await mock_session_old.get_program_price("cacacacacacaca")
        assert response == expected_model_old


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
