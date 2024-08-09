from decimal import Decimal

from eth_utils import to_normalized_address, to_wei
from superfluid import CFA_V1, Operation, Web3FlowInfo
from web3 import Web3
from web3.types import TxParams

from aleph.sdk.conf import settings
from src.aleph.sdk.chains.ethereum import ETHAccount


class SuperFluid(ETHAccount):

    def __init__(self, private_key: bytes):
        super().__init__(private_key)
        self.cfaV1Instance = CFA_V1(settings.AVAX_RPC, settings.AVAX_CHAIN_ID)

    async def sign_and_send_transaction(self, tx_params: TxParams, rpc: str) -> str:
        """
        Signs and broadcasts a transaction using ETHAccount
        @param tx_params - Transaction parameters
        @param rpc - RPC URL
        @returns - str - The transaction hash
        """
        web3 = Web3(Web3.HTTPProvider(rpc))
        local_account = self._account
        signed_txn = local_account.sign_transaction(tx_params)
        transaction_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return transaction_hash.hex()

    async def execute_operation_with_account(self, operation: Operation) -> str:
        """
        Executes the operation using ETHAccount
        @param operation - Operation instance from the library
        @returns - str - The transaction hash
        @returns - str - The transaction hash
        """
        populated_transaction = operation._get_populated_transaction_request(
            operation.rpc, self._account.key
        )
        transaction_hash = await self.sign_and_send_transaction(
            populated_transaction, operation.rpc
        )
        return transaction_hash

    async def create_flow(self, sender: str, receiver: str, flow: Decimal) -> str:
        return await self.execute_operation_with_account(
            self.cfaV1Instance.create_flow(
                sender=to_normalized_address(sender),
                receiver=to_normalized_address(receiver),
                super_token=settings.ALEPH_SUPER_TOKEN,
                flow_rate=to_wei(Decimal(flow), "ether"),
            )
        )

    async def delete_flow(self, sender: str, receiver: str) -> str:
        return await self.execute_operation_with_account(
            self.cfaV1Instance.delete_flow(
                sender=to_normalized_address(sender),
                receiver=to_normalized_address(receiver),
                super_token=settings.ALEPH_SUPER_TOKEN,
            )
        )

    async def update_flow(self, sender: str, receiver: str, flow: float) -> str:
        return await self.execute_operation_with_account(
            self.cfaV1Instance.update_flow(
                sender=to_normalized_address(sender),
                receiver=to_normalized_address(receiver),
                super_token=settings.ALEPH_SUPER_TOKEN,
                flow_rate=to_wei(Decimal(flow), "ether"),
            )
        )

    async def get_flow(self, sender: str, receiver: str) -> Web3FlowInfo:
        return self.cfaV1Instance.get_flow(
            sender=to_normalized_address(sender),
            receiver=to_normalized_address(receiver),
            super_token=settings.ALEPH_SUPER_TOKEN,
        )
