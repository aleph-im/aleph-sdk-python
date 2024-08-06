from unittest.mock import AsyncMock

import pytest

from aleph.sdk.client import AlephHttpClient
from aleph.sdk.exceptions import InvalidHashError
from aleph.sdk.query.responses import PriceResponse


def make_mock_price_client(item_hash: str):
    mock_client = AsyncMock(spec=AlephHttpClient)
    if item_hash == "valid_item_hash":
        mock_client.get_program_price.return_value = PriceResponse(
            required_tokens=3.0555555555555556e-06, payment_type="superfluid"
        )
    elif item_hash == "invalid_item_hash":
        mock_client.get_program_price.side_effect = InvalidHashError("Invalid hash")
    else:
        raise NotImplementedError(f"Mock not implemented for item_hash: {item_hash}")
    return mock_client


@pytest.mark.asyncio
async def test_get_program_price_valid():
    item_hash = "valid_item_hash"
    mock_client = make_mock_price_client(item_hash)

    response = await mock_client.get_program_price(item_hash)

    assert response.required_tokens == 3.0555555555555556e-06
    assert response.payment_type == "superfluid"


@pytest.mark.asyncio
async def test_get_program_price_invalid():
    item_hash = "invalid_item_hash"
    mock_client = make_mock_price_client(item_hash)

    with pytest.raises(InvalidHashError):
        await mock_client.get_program_price(item_hash)
