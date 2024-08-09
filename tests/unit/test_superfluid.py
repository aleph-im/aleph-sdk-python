import random
from decimal import Decimal
from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph_message.models import Chain
from eth_utils import to_checksum_address
from superfluid import Operation, Web3FlowInfo

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.conf import settings


def generate_fake_eth_address():
    return to_checksum_address(
        "0x" + "".join([random.choice("0123456789abcdef") for _ in range(40)])
    )


@pytest.fixture
def mock_superfluid():
    with patch("aleph.sdk.connectors.superfluid.CFA_V1") as MockCFA_V1:
        yield MockCFA_V1.return_value


@pytest.fixture
def eth_account(mock_superfluid):
    private_key = b"\x01" * 32
    return ETHAccount(
        private_key,
        chain=Chain.AVAX,
        rpc=settings.AVAX_RPC,
        chain_id=settings.AVAX_CHAIN_ID,
    )


@pytest.mark.asyncio
async def test_initialization(eth_account):
    assert eth_account.superfluid_connector is not None


@pytest.mark.asyncio
async def test_create_flow(eth_account, mock_superfluid):
    mock_operation = AsyncMock(spec=Operation)
    mock_superfluid.create_flow.return_value = mock_operation

    sender = eth_account.get_address()
    receiver = generate_fake_eth_address()
    flow = Decimal("10.0")

    with patch(
        "aleph.sdk.connectors.superfluid.execute_operation_with_account",
        return_value="0xTransactionHash",
    ) as mock_execute:
        tx_hash = await eth_account.create_flow(receiver, flow)
        assert tx_hash == "0xTransactionHash"
        mock_execute.assert_called_once_with(
            account=eth_account._account, operation=mock_operation
        )
        mock_superfluid.create_flow.assert_called_once_with(
            sender=sender.lower(),
            receiver=receiver.lower(),
            super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
            flow_rate=mock.ANY,
        )


@pytest.mark.asyncio
async def test_delete_flow(eth_account, mock_superfluid):
    mock_operation = AsyncMock(spec=Operation)
    mock_superfluid.delete_flow.return_value = mock_operation

    sender = eth_account.get_address()
    receiver = generate_fake_eth_address()

    with patch(
        "aleph.sdk.connectors.superfluid.execute_operation_with_account",
        return_value="0xTransactionHash",
    ) as mock_execute:
        tx_hash = await eth_account.delete_flow(receiver)
        assert tx_hash == "0xTransactionHash"
        mock_execute.assert_called_once_with(
            account=eth_account._account, operation=mock_operation
        )
        mock_superfluid.delete_flow.assert_called_once_with(
            sender=sender.lower(),
            receiver=receiver.lower(),
            super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
        )


@pytest.mark.asyncio
async def test_update_flow(eth_account, mock_superfluid):
    mock_operation = AsyncMock(spec=Operation)
    mock_superfluid.update_flow.return_value = mock_operation

    sender = eth_account.get_address()
    receiver = generate_fake_eth_address()
    flow = Decimal(15.0)

    with patch(
        "aleph.sdk.connectors.superfluid.execute_operation_with_account",
        return_value="0xTransactionHash",
    ) as mock_execute:
        tx_hash = await eth_account.update_flow(receiver, flow)
        assert tx_hash == "0xTransactionHash"
        mock_execute.assert_called_once_with(
            account=eth_account._account, operation=mock_operation
        )
        mock_superfluid.update_flow.assert_called_once_with(
            sender=sender.lower(),
            receiver=receiver.lower(),
            super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
            flow_rate=mock.ANY,
        )


@pytest.mark.asyncio
async def test_get_flow(eth_account, mock_superfluid):
    mock_flow_info = MagicMock(spec=Web3FlowInfo)
    mock_superfluid.get_flow.return_value = mock_flow_info

    sender = eth_account.get_address()
    receiver = generate_fake_eth_address()

    flow_info = await eth_account.get_flow(receiver)
    assert flow_info == mock_flow_info
    mock_superfluid.get_flow.assert_called_once_with(
        sender=sender.lower(),
        receiver=receiver.lower(),
        super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
    )
