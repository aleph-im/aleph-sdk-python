from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest
from aleph_message.models import Chain
from web3.exceptions import ContractCustomError
from web3.types import TxParams

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.connectors.superfluid import Superfluid
from aleph.sdk.exceptions import InsufficientFundsError
from aleph.sdk.types import TokenType


@pytest.fixture
def mock_eth_account():
    private_key = b"\x01" * 32
    account = ETHAccount(
        private_key,
        chain=Chain.ETH,
    )
    account._provider = MagicMock()
    account._provider.eth = MagicMock()
    account._provider.eth.gas_price = 20_000_000_000  # 20 Gwei
    account._provider.eth.estimate_gas = MagicMock(
        return_value=100_000
    )  # 100k gas units

    # Mock get_eth_balance to return a specific balance
    with patch.object(account, "get_eth_balance", return_value=10**18):  # 1 ETH
        yield account


@pytest.fixture
def mock_superfluid(mock_eth_account):
    superfluid = Superfluid(mock_eth_account)
    superfluid.cfaV1Instance = MagicMock()
    superfluid.cfaV1Instance.create_flow = MagicMock()
    superfluid.super_token = "0xsupertokenaddress"
    superfluid.normalized_address = "0xsenderaddress"

    # Mock the operation
    operation = MagicMock()
    operation._get_populated_transaction_request = MagicMock(
        return_value={"value": 0, "gas": 100000, "gasPrice": 20_000_000_000}
    )
    superfluid.cfaV1Instance.create_flow.return_value = operation

    return superfluid


class TestGasEstimation:
    def test_can_transact_with_sufficient_funds(self, mock_eth_account):
        tx = TxParams({"to": "0xreceiver", "value": 0})

        # Should pass with 1 ETH balance against ~0.002 ETH gas cost
        assert mock_eth_account.can_transact(tx=tx, block=True) is True

    def test_can_transact_with_insufficient_funds(self, mock_eth_account):
        tx = TxParams({"to": "0xreceiver", "value": 0})

        # Set balance to almost zero
        with patch.object(mock_eth_account, "get_eth_balance", return_value=1000):
            # Should raise InsufficientFundsError
            with pytest.raises(InsufficientFundsError) as exc_info:
                mock_eth_account.can_transact(tx=tx, block=True)

        assert exc_info.value.token_type == TokenType.GAS

    def test_can_transact_with_legacy_gas_price(self, mock_eth_account):
        tx = TxParams(
            {"to": "0xreceiver", "value": 0, "gasPrice": 30_000_000_000}  # 30 Gwei
        )

        # Should use the tx's gasPrice instead of default
        mock_eth_account.can_transact(tx=tx, block=True)

        # It should have used the tx's gasPrice for calculation
        mock_eth_account._provider.eth.estimate_gas.assert_called_once()

    def test_can_transact_with_eip1559_gas(self, mock_eth_account):
        tx = TxParams(
            {"to": "0xreceiver", "value": 0, "maxFeePerGas": 40_000_000_000}  # 40 Gwei
        )

        # Should use the tx's maxFeePerGas
        mock_eth_account.can_transact(tx=tx, block=True)

        # It should have used the tx's maxFeePerGas for calculation
        mock_eth_account._provider.eth.estimate_gas.assert_called_once()

    def test_can_transact_with_contract_error(self, mock_eth_account):
        tx = TxParams({"to": "0xreceiver", "value": 0})

        # Make estimate_gas throw a ContractCustomError
        mock_eth_account._provider.eth.estimate_gas.side_effect = ContractCustomError(
            "error"
        )

        # Should fallback to MIN_ETH_BALANCE_WEI
        mock_eth_account.can_transact(tx=tx, block=True)

        # It should have called estimate_gas
        mock_eth_account._provider.eth.estimate_gas.assert_called_once()


class TestSuperfluidFlowEstimation:
    @pytest.mark.asyncio
    async def test_simulate_create_tx_flow_success(
        self, mock_superfluid, mock_eth_account
    ):
        # Patch the can_transact method to simulate a successful transaction
        with patch.object(mock_eth_account, "can_transact", return_value=True):
            result = mock_superfluid._simulate_create_tx_flow(Decimal("0.00000005"))
            assert result is True

            # Verify the flow was correctly simulated but not executed
            mock_superfluid.cfaV1Instance.create_flow.assert_called_once()
            assert "0x0000000000000000000000000000000000000001" in str(
                mock_superfluid.cfaV1Instance.create_flow.call_args
            )

    @pytest.mark.asyncio
    async def test_simulate_create_tx_flow_contract_error(
        self, mock_superfluid, mock_eth_account
    ):
        # Setup a contract error code for insufficient deposit
        error = ContractCustomError("Insufficient deposit")
        error.data = "0xea76c9b3"  # This is the specific error code checked in the code

        # Mock can_transact to throw the error
        with patch.object(mock_eth_account, "can_transact", side_effect=error):
            # Also mock get_super_token_balance for the error case
            with patch.object(
                mock_eth_account, "get_super_token_balance", return_value=0
            ):
                # Should raise InsufficientFundsError for ALEPH token
                with pytest.raises(InsufficientFundsError) as exc_info:
                    mock_superfluid._simulate_create_tx_flow(Decimal("0.00000005"))

                assert exc_info.value.token_type == TokenType.ALEPH

    @pytest.mark.asyncio
    async def test_simulate_create_tx_flow_other_error(
        self, mock_superfluid, mock_eth_account
    ):
        # Setup a different contract error code
        error = ContractCustomError("Other error")
        error.data = "0xsomeothercode"

        # Mock can_transact to throw the error
        with patch.object(mock_eth_account, "can_transact", side_effect=error):
            # Should return False for other errors
            result = mock_superfluid._simulate_create_tx_flow(Decimal("0.00000005"))
            assert result is False

    @pytest.mark.asyncio
    async def test_can_start_flow_uses_simulation(self, mock_superfluid):
        # Mock _simulate_create_tx_flow to verify it's called
        with patch.object(
            mock_superfluid, "_simulate_create_tx_flow", return_value=True
        ) as mock_simulate:
            result = mock_superfluid.can_start_flow(Decimal("0.00000005"))

            assert result is True
            mock_simulate.assert_called_once_with(
                flow=Decimal("0.00000005"), block=True
            )
