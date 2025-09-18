from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Optional

from eth_utils import to_normalized_address
from superfluid import CFA_V1, Operation, Web3FlowInfo
from web3.exceptions import ContractCustomError

from aleph.sdk.evm_utils import (
    FlowUpdate,
    from_wei_token,
    get_super_token_address,
    to_wei_token,
)
from aleph.sdk.exceptions import InsufficientFundsError
from aleph.sdk.types import TokenType

if TYPE_CHECKING:
    from aleph.sdk.chains.ethereum import ETHAccount


class Superfluid:
    """
    Wrapper around the Superfluid APIs in order to CRUD Superfluid flows between two accounts.
    """

    account: ETHAccount
    normalized_address: str
    super_token: str
    cfaV1Instance: CFA_V1
    MIN_4_HOURS = 60 * 60 * 4

    def __init__(self, account: ETHAccount):
        self.account = account
        self.normalized_address = to_normalized_address(account.get_address())
        if account.chain:
            self.super_token = str(get_super_token_address(account.chain))
            self.cfaV1Instance = CFA_V1(account.rpc, account.chain_id)

    def _simulate_create_tx_flow(self, flow: Decimal, block=True) -> bool:
        try:
            operation = self.cfaV1Instance.create_flow(
                sender=self.normalized_address,
                receiver=to_normalized_address(
                    "0x0000000000000000000000000000000000000001"
                ),  # Fake Address we do not sign/send this transactions
                super_token=self.super_token,
                flow_rate=int(to_wei_token(flow)),
            )

            populated_transaction = operation._get_populated_transaction_request(
                self.account.rpc, self.account._account.key
            )
            return self.account.can_transact(tx=populated_transaction, block=block)
        except ContractCustomError as e:
            if getattr(e, "data", None) == "0xea76c9b3":
                balance = self.account.get_super_token_balance()
                MIN_FLOW_4H = to_wei_token(flow) * Decimal(self.MIN_4_HOURS)
                raise InsufficientFundsError(
                    token_type=TokenType.ALEPH,
                    required_funds=float(from_wei_token(MIN_FLOW_4H)),
                    available_funds=float(from_wei_token(balance)),
                )
            return False

    async def _execute_operation_with_account(self, operation: Operation) -> str:
        """
        Execute an operation using the provided ETHAccount
        @param operation - Operation instance from the library
        @returns - str - Transaction hash
        """
        populated_transaction = operation._get_populated_transaction_request(
            self.account.rpc, self.account._account.key
        )
        self.account.can_transact(tx=populated_transaction)

        return await self.account._sign_and_send_transaction(populated_transaction)

    def can_start_flow(self, flow: Decimal, block=True) -> bool:
        """Check if the account has enough funds to start a Superfluid flow of the given size."""
        return self._simulate_create_tx_flow(flow=flow, block=block)

    async def create_flow(self, receiver: str, flow: Decimal) -> str:
        """Create a Superfluid flow between two addresses."""
        return await self._execute_operation_with_account(
            operation=self.cfaV1Instance.create_flow(
                sender=self.normalized_address,
                receiver=to_normalized_address(receiver),
                super_token=self.super_token,
                flow_rate=int(to_wei_token(flow)),
            ),
        )

    async def get_flow(self, sender: str, receiver: str) -> Web3FlowInfo:
        """Fetch information about the Superfluid flow between two addresses."""
        return self.cfaV1Instance.get_flow(
            sender=to_normalized_address(sender),
            receiver=to_normalized_address(receiver),
            super_token=self.super_token,
        )

    async def delete_flow(self, receiver: str) -> str:
        """Delete the Supefluid flow between two addresses."""
        return await self._execute_operation_with_account(
            operation=self.cfaV1Instance.delete_flow(
                sender=self.normalized_address,
                receiver=to_normalized_address(receiver),
                super_token=self.super_token,
            ),
        )

    async def update_flow(self, receiver: str, flow: Decimal) -> str:
        """Update the flow of a Superfluid flow between two addresses."""
        return await self._execute_operation_with_account(
            operation=self.cfaV1Instance.update_flow(
                sender=self.normalized_address,
                receiver=to_normalized_address(receiver),
                super_token=self.super_token,
                flow_rate=int(to_wei_token(flow)),
            ),
        )

    async def manage_flow(
        self,
        receiver: str,
        flow: Decimal,
        update_type: FlowUpdate,
    ) -> Optional[str]:
        """
        Update the flow of a Superfluid stream between a sender and receiver.
        This function either increases or decreases the flow rate between the sender and receiver,
        based on the update_type. If no flow exists and the update type is augmentation, it creates a new flow
        with the specified rate. If the update type is reduction and the reduction amount brings the flow to zero
        or below, the flow is deleted.

        :param receiver: Address of the receiver in hexadecimal format.
        :param flow: The flow rate to be added or removed (in ether).
        :param update_type: The type of update to perform (augmentation or reduction).
        :return: The transaction hash of the executed operation (create, update, or delete flow).
        """

        # Retrieve current flow info
        flow_info: Web3FlowInfo = await self.account.get_flow(receiver)

        current_flow_rate_wei: Decimal = Decimal(flow_info["flowRate"] or 0)
        flow_rate_wei: int = int(to_wei_token(flow))

        if update_type == FlowUpdate.INCREASE:
            if current_flow_rate_wei > 0:
                # Update existing flow by increasing the rate
                new_flow_rate_wei = current_flow_rate_wei + flow_rate_wei
                new_flow_rate_ether = from_wei_token(new_flow_rate_wei)
                return await self.account.update_flow(receiver, new_flow_rate_ether)
            else:
                # Create a new flow if none exists
                return await self.account.create_flow(receiver, flow)
        else:
            if current_flow_rate_wei > 0:
                # Reduce the existing flow
                new_flow_rate_wei = current_flow_rate_wei - flow_rate_wei
                # Ensure to not leave infinitesimal flows
                # Often, there were 1-10 wei remaining in the flow rate, which prevented the flow from being deleted
                if new_flow_rate_wei > 99:
                    new_flow_rate_ether = from_wei_token(new_flow_rate_wei)
                    return await self.account.update_flow(receiver, new_flow_rate_ether)
                else:
                    # Delete the flow if the new flow rate is zero or negative
                    return await self.account.delete_flow(receiver)
        return None
