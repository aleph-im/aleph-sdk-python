import pytest

from aleph.sdk.query.responses import AddressCreditResponse, CreditsResponse
from tests.unit.conftest import make_mock_get_session


@pytest.mark.asyncio
async def test_get_credits():
    """
    Test that the get_credits method returns the correct CreditsResponse
    when called on the AlephHttpClient.
    """
    # Mock data from the example
    credits_data = {
        "credit_balances": [
            {
                "address": "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B57d",
                "credits": 100000,
            },
            {
                "address": "0x28152dDF5cd213F341c8104d5361bBe41e95b301",
                "credits": 1000000,
            },
        ],
        "pagination_per_page": 100,
        "pagination_page": 1,
        "pagination_total": 0,
        "pagination_item": "credit_balances",
    }

    # Create mock client with the predefined response
    mock_client = make_mock_get_session(credits_data)

    # Test the method
    async with mock_client:
        response = await mock_client.get_credits()

        # Verify the response structure
        assert isinstance(response, CreditsResponse)
        assert response.pagination_page == 1
        assert response.pagination_per_page == 100
        assert response.pagination_item == "credit_balances"

        # Verify the credit balances
        assert len(response.credit_balances) == 2

        # Check first credit balance
        first_balance = response.credit_balances[0]
        assert isinstance(first_balance, AddressCreditResponse)
        assert first_balance.address == "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B57d"
        assert first_balance.credits == 100000

        # Check second credit balance
        second_balance = response.credit_balances[1]
        assert isinstance(second_balance, AddressCreditResponse)
        assert second_balance.address == "0x28152dDF5cd213F341c8104d5361bBe41e95b301"
        assert second_balance.credits == 1000000


@pytest.mark.asyncio
async def test_get_credit_balance():
    """
    Test that the get_credit_balance method returns the correct AddressCreditResponse
    for a specific address when called on the AlephHttpClient.
    """
    # Mock data from the example
    credit_balance_data = {
        "address": "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B57d",
        "credits": 100000,
    }

    # Create mock client with the predefined response
    mock_client = make_mock_get_session(credit_balance_data)

    # Test the method with a specific address
    address = "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B57d"
    async with mock_client:
        response = await mock_client.get_credit_balance(address)

        # Verify the response
        assert isinstance(response, AddressCreditResponse)
        assert response.address == address
        assert response.credits == 100000
