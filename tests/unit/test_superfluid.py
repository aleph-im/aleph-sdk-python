import random
from decimal import Decimal
from unittest.mock import AsyncMock, patch

import pytest
from aleph_message.models import Chain
from eth_utils import to_checksum_address

from aleph.sdk.chains.ethereum import ETHAccount


def generate_fake_eth_address():
    return to_checksum_address(
        "0x" + "".join([random.choice("0123456789abcdef") for _ in range(40)])
    )


@pytest.fixture
def mock_superfluid():
    with patch("aleph.sdk.connectors.superfluid.Superfluid") as MockSuperfluid:
        mock_superfluid = MockSuperfluid.return_value

        # Mock methods for the Superfluid connector
        mock_superfluid.create_flow = AsyncMock(return_value="0xTransactionHash")
        mock_superfluid.delete_flow = AsyncMock(return_value="0xTransactionHash")
        mock_superfluid.update_flow = AsyncMock(return_value="0xTransactionHash")

        # Mock get_flow to return a mock Web3FlowInfo
        mock_flow_info = {"timestamp": 0, "flowRate": 0, "deposit": 0, "owedDeposit": 0}
        mock_superfluid.get_flow = AsyncMock(return_value=mock_flow_info)

        yield mock_superfluid


@pytest.fixture
def eth_account(mock_superfluid):
    private_key = b"\x01" * 32
    account = ETHAccount(
        private_key,
        chain=Chain.AVAX,
    )
    with patch.object(
        account, "get_super_token_balance", new_callable=AsyncMock
    ) as mock_get_balance:
        mock_get_balance.return_value = Decimal("1")
        with patch.object(
            account, "can_transact", new_callable=AsyncMock
        ) as mock_can_transact:
            mock_can_transact.return_value = True
            account.superfluid_connector = mock_superfluid
            yield account


@pytest.mark.asyncio
async def test_initialization(eth_account):
    assert eth_account.superfluid_connector is not None


@pytest.mark.asyncio
async def test_create_flow(eth_account, mock_superfluid):
    receiver = generate_fake_eth_address()
    flow = Decimal("0.00000005")

    tx_hash = await eth_account.create_flow(receiver, flow)

    assert tx_hash == "0xTransactionHash"
    mock_superfluid.create_flow.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_flow(eth_account, mock_superfluid):
    receiver = generate_fake_eth_address()

    tx_hash = await eth_account.delete_flow(receiver)

    assert tx_hash == "0xTransactionHash"
    mock_superfluid.delete_flow.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_flow(eth_account, mock_superfluid):
    receiver = generate_fake_eth_address()
    flow = Decimal("0.005")

    tx_hash = await eth_account.update_flow(receiver, flow)

    assert tx_hash == "0xTransactionHash"
    mock_superfluid.update_flow.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_flow(eth_account, mock_superfluid):
    receiver = generate_fake_eth_address()

    flow_info = await eth_account.get_flow(receiver)

    assert flow_info["timestamp"] == 0
    assert flow_info["flowRate"] == 0
    assert flow_info["deposit"] == 0
    assert flow_info["owedDeposit"] == 0
