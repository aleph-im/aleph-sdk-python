from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import TYPE_CHECKING, Optional

from eth_utils import to_normalized_address, to_wei
from superfluid import CFA_V1, Operation, Web3FlowInfo
from web3 import Web3
from web3.types import TxParams

from aleph.sdk.conf import settings

if TYPE_CHECKING:
    from aleph.sdk.chains.ethereum import LocalAccount


async def sign_and_send_transaction(
    account: LocalAccount, tx_params: TxParams, rpc: str
) -> str:
    """
    Sign and broadcast a transaction using the provided ETHAccount

    @param tx_params - Transaction parameters
    @param rpc - RPC URL
    @returns - str - The transaction hash
    """
    web3 = Web3(Web3.HTTPProvider(rpc))

    def sign_and_send():
        signed_txn = account.sign_transaction(tx_params)
        transaction_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return transaction_hash.hex()

    # Sending a transaction is done over HTTP(S) and implemented using a blocking
    # API in `web3.eth`. This runs it in a non-blocking asyncio executor.
    loop = asyncio.get_running_loop()
    transaction_hash = await loop.run_in_executor(None, sign_and_send)
    return transaction_hash


async def execute_operation_with_account(
    account: LocalAccount, operation: Operation
) -> str:
    """
    Execute an operation using the provided ETHAccount

    @param operation - Operation instance from the library
    @returns - str - The transaction hash
    @returns - str - The transaction hash
    """
    populated_transaction = operation._get_populated_transaction_request(
        operation.rpc, account.key
    )
    transaction_hash = await sign_and_send_transaction(
        account, populated_transaction, operation.rpc
    )
    return transaction_hash


class Superfluid:
    """
    Wrapper around the Superfluid APIs in order to CRUD Superfluid flows between two accounts.
    """

    account: Optional[LocalAccount]

    def __init__(
        self,
        rpc=settings.AVAX_RPC,
        chain_id=settings.AVAX_CHAIN_ID,
        account: Optional[LocalAccount] = None,
    ):
        self.cfaV1Instance = CFA_V1(rpc, chain_id)
        self.account = account

    async def create_flow(self, sender: str, receiver: str, flow: Decimal) -> str:
        """Create a Superfluid flow between two addresses."""
        if not self.account:
            raise ValueError("An account is required to create a flow")
        return await execute_operation_with_account(
            account=self.account,
            operation=self.cfaV1Instance.create_flow(
                sender=to_normalized_address(sender),
                receiver=to_normalized_address(receiver),
                super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
                flow_rate=to_wei(Decimal(flow), "ether"),
            ),
        )

    async def get_flow(self, sender: str, receiver: str) -> Web3FlowInfo:
        """Fetch information about the Superfluid flow between two addresses."""
        return self.cfaV1Instance.get_flow(
            sender=to_normalized_address(sender),
            receiver=to_normalized_address(receiver),
            super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
        )

    async def delete_flow(self, sender: str, receiver: str) -> str:
        """Delete the Supefluid flow between two addresses."""
        if not self.account:
            raise ValueError("An account is required to delete a flow")
        return await execute_operation_with_account(
            account=self.account,
            operation=self.cfaV1Instance.delete_flow(
                sender=to_normalized_address(sender),
                receiver=to_normalized_address(receiver),
                super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
            ),
        )

    async def update_flow(self, sender: str, receiver: str, flow: Decimal) -> str:
        """Update the flow of a Superfluid flow between two addresses."""
        if not self.account:
            raise ValueError("An account is required to update a flow")
        return await execute_operation_with_account(
            account=self.account,
            operation=self.cfaV1Instance.update_flow(
                sender=to_normalized_address(sender),
                receiver=to_normalized_address(receiver),
                super_token=settings.AVAX_ALEPH_SUPER_TOKEN,
                flow_rate=to_wei(Decimal(flow), "ether"),
            ),
        )
