import random
from decimal import Decimal
from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_utils import to_checksum_address
from superfluid import Operation, Web3FlowInfo

from aleph.sdk.client.superfluid import SuperFluid
from aleph.sdk.conf import settings


def generate_fake_eth_address():
    return to_checksum_address(
        "0x" + "".join([random.choice("0123456789abcdef") for _ in range(40)])
    )


@pytest.fixture
def mock_cfa_v1():
    with patch("aleph.sdk.client.superfluid.CFA_V1") as MockCFA_V1:
        yield MockCFA_V1.return_value


@pytest.fixture
def superfluid(mock_cfa_v1):
    private_key = b"\x01" * 32  # Example private key, use a proper one for your tests
    return SuperFluid(private_key)


@pytest.mark.asyncio
async def test_initialization(mock_cfa_v1):
    private_key = b"\x01" * 32  # Example private key
    superfluid = SuperFluid(private_key)

    assert isinstance(superfluid, SuperFluid)


@pytest.mark.asyncio
async def test_create_flow(superfluid, mock_cfa_v1):
    mock_operation = AsyncMock(spec=Operation)
    mock_cfa_v1.create_flow.return_value = mock_operation

    sender = generate_fake_eth_address()
    receiver = generate_fake_eth_address()
    flow = Decimal("10.0")

    with patch.object(
        superfluid, "execute_operation_with_account", return_value="0xTransactionHash"
    ) as mock_execute:
        tx_hash = await superfluid.create_flow(sender, receiver, flow)
        assert tx_hash == "0xTransactionHash"
        mock_execute.assert_called_once_with(mock_operation)
        mock_cfa_v1.create_flow.assert_called_once_with(
            sender=sender.lower(),
            receiver=receiver.lower(),
            super_token=settings.ALEPH_SUPER_TOKEN,
            flow_rate=mock.ANY,
        )


@pytest.mark.asyncio
async def test_delete_flow(superfluid, mock_cfa_v1):
    mock_operation = AsyncMock(spec=Operation)
    mock_cfa_v1.delete_flow.return_value = mock_operation

    sender = generate_fake_eth_address()
    receiver = generate_fake_eth_address()

    with patch.object(
        superfluid, "execute_operation_with_account", return_value="0xTransactionHash"
    ) as mock_execute:
        tx_hash = await superfluid.delete_flow(sender, receiver)
        assert tx_hash == "0xTransactionHash"
        mock_execute.assert_called_once_with(mock_operation)
        mock_cfa_v1.delete_flow.assert_called_once_with(
            sender=sender.lower(),
            receiver=receiver.lower(),
            super_token=settings.ALEPH_SUPER_TOKEN,
        )


@pytest.mark.asyncio
async def test_update_flow(superfluid, mock_cfa_v1):
    mock_operation = AsyncMock(spec=Operation)
    mock_cfa_v1.update_flow.return_value = mock_operation

    sender = generate_fake_eth_address()
    receiver = generate_fake_eth_address()
    flow = 15.0

    with patch.object(
        superfluid, "execute_operation_with_account", return_value="0xTransactionHash"
    ) as mock_execute:
        tx_hash = await superfluid.update_flow(sender, receiver, flow)
        assert tx_hash == "0xTransactionHash"
        mock_execute.assert_called_once_with(mock_operation)
        mock_cfa_v1.update_flow.assert_called_once_with(
            sender=sender.lower(),
            receiver=receiver.lower(),
            super_token=settings.ALEPH_SUPER_TOKEN,
            flow_rate=mock.ANY,
        )


@pytest.mark.asyncio
async def test_get_flow(superfluid, mock_cfa_v1):
    mock_flow_info = MagicMock(spec=Web3FlowInfo)
    mock_cfa_v1.get_flow.return_value = mock_flow_info

    sender = generate_fake_eth_address()
    receiver = generate_fake_eth_address()

    flow_info = await superfluid.get_flow(sender, receiver)
    assert flow_info == mock_flow_info
    mock_cfa_v1.get_flow.assert_called_once_with(
        sender=sender.lower(),
        receiver=receiver.lower(),
        super_token=settings.ALEPH_SUPER_TOKEN,
    )
