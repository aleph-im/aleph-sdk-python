from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

from eth_utils import to_normalized_address
from superfluid import CFA_V1, Operation, Web3FlowInfo

from aleph.sdk.exceptions import InsufficientFundsError

from ..evm_utils import get_super_token_address, to_human_readable_token, to_wei_token

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

    async def _execute_operation_with_account(self, operation: Operation) -> str:
        """
        Execute an operation using the provided ETHAccount
        @param operation - Operation instance from the library
        @returns - str - Transaction hash
        """
        populated_transaction = operation._get_populated_transaction_request(
            self.account.rpc, self.account._account.key
        )
        return await self.account._sign_and_send_transaction(populated_transaction)

    def can_start_flow(self, flow: Decimal, block=True) -> bool:
        valid = False
        if self.account.can_transact(block=block):
            balance = self.account.get_super_token_balance()
            MIN_FLOW_4H = to_wei_token(flow) * Decimal(self.MIN_4_HOURS)
            valid = balance > MIN_FLOW_4H
            if not valid and block:
                raise InsufficientFundsError(
                    required_funds=float(MIN_FLOW_4H),
                    available_funds=to_human_readable_token(balance),
                )
        return valid

    async def create_flow(self, receiver: str, flow: Decimal) -> str:
        """Create a Superfluid flow between two addresses."""
        self.can_start_flow(flow)
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
