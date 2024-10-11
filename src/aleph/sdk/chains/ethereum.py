import asyncio
import base64
from decimal import Decimal
from pathlib import Path
from typing import Awaitable, Optional, Union

from aleph_message.models import Chain
from eth_account import Account  # type: ignore
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from eth_keys.exceptions import BadSignature as EthBadSignatureError
from superfluid import Web3FlowInfo
from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.types import TxParams, TxReceipt

from aleph.sdk.exceptions import InsufficientFundsError

from ..conf import settings
from ..connectors.superfluid import Superfluid
from ..evm_utils import (
    BALANCEOF_ABI,
    MIN_ETH_BALANCE,
    MIN_ETH_BALANCE_WEI,
    get_chain_id,
    get_chains_with_super_token,
    get_rpc,
    get_super_token_address,
    get_token_address,
    to_human_readable_token,
)
from ..exceptions import BadSignatureError
from ..utils import bytes_from_hex
from .common import BaseAccount, get_fallback_private_key, get_public_key


class ETHAccount(BaseAccount):
    """Interact with an Ethereum address or key pair on EVM blockchains"""

    CHAIN = "ETH"
    CURVE = "secp256k1"
    _account: LocalAccount
    _provider: Optional[Web3]
    chain: Optional[Chain]
    chain_id: Optional[int]
    rpc: Optional[str]
    superfluid_connector: Optional[Superfluid]

    def __init__(
        self,
        private_key: bytes,
        chain: Optional[Chain] = None,
    ):
        self.private_key = private_key
        self._account: LocalAccount = Account.from_key(self.private_key)
        self.connect_chain(chain=chain)

    @staticmethod
    def from_mnemonic(mnemonic: str, chain: Optional[Chain] = None) -> "ETHAccount":
        Account.enable_unaudited_hdwallet_features()
        return ETHAccount(
            private_key=Account.from_mnemonic(mnemonic=mnemonic).key, chain=chain
        )

    def export_private_key(self) -> str:
        """Export the private key using standard format."""
        return f"0x{base64.b16encode(self.private_key).decode().lower()}"

    def get_address(self) -> str:
        return self._account.address

    def get_public_key(self) -> str:
        return "0x" + get_public_key(private_key=self._account.key).hex()

    async def sign_raw(self, buffer: bytes) -> bytes:
        """Sign a raw buffer."""
        msghash = encode_defunct(text=buffer.decode("utf-8"))
        sig = self._account.sign_message(msghash)
        return sig["signature"]

    def connect_chain(self, chain: Optional[Chain] = None):
        self.chain = chain
        if self.chain:
            self.chain_id = get_chain_id(self.chain)
            self.rpc = get_rpc(self.chain)
            self._provider = Web3(Web3.HTTPProvider(self.rpc))
            if chain == Chain.BSC:
                self._provider.middleware_onion.inject(
                    geth_poa_middleware, "geth_poa", layer=0
                )
        else:
            self.chain_id = None
            self.rpc = None
            self._provider = None

        if chain in get_chains_with_super_token() and self._provider:
            self.superfluid_connector = Superfluid(self)
        else:
            self.superfluid_connector = None

    def switch_chain(self, chain: Optional[Chain] = None):
        self.connect_chain(chain=chain)

    def can_transact(self, block=True) -> bool:
        balance = self.get_eth_balance()
        valid = balance > MIN_ETH_BALANCE_WEI if self.chain else False
        if not valid and block:
            raise InsufficientFundsError(
                required_funds=MIN_ETH_BALANCE,
                available_funds=to_human_readable_token(balance),
            )
        return valid

    async def _sign_and_send_transaction(self, tx_params: TxParams) -> str:
        """
        Sign and broadcast a transaction using the provided ETHAccount
        @param tx_params - Transaction parameters
        @returns - str - Transaction hash
        """
        self.can_transact()

        def sign_and_send() -> TxReceipt:
            if self._provider is None:
                raise ValueError("Provider not connected")
            signed_tx = self._provider.eth.account.sign_transaction(
                tx_params, self._account.key
            )
            tx_hash = self._provider.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_receipt = self._provider.eth.wait_for_transaction_receipt(
                tx_hash, settings.TX_TIMEOUT
            )
            return tx_receipt

        loop = asyncio.get_running_loop()
        tx_receipt = await loop.run_in_executor(None, sign_and_send)
        return tx_receipt["transactionHash"].hex()

    def get_eth_balance(self) -> Decimal:
        return Decimal(
            self._provider.eth.get_balance(self._account.address)
            if self._provider
            else 0
        )

    def get_token_balance(self) -> Decimal:
        if self.chain and self._provider:
            contact_address = get_token_address(self.chain)
            if contact_address:
                contract = self._provider.eth.contract(
                    address=contact_address, abi=BALANCEOF_ABI
                )
                return Decimal(contract.functions.balanceOf(self.get_address()).call())
        return Decimal(0)

    def get_super_token_balance(self) -> Decimal:
        if self.chain and self._provider:
            contact_address = get_super_token_address(self.chain)
            if contact_address:
                contract = self._provider.eth.contract(
                    address=contact_address, abi=BALANCEOF_ABI
                )
                return Decimal(contract.functions.balanceOf(self.get_address()).call())
        return Decimal(0)

    def create_flow(self, receiver: str, flow: Decimal) -> Awaitable[str]:
        """Creat a Superfluid flow between this account and the receiver address."""
        if not self.superfluid_connector:
            raise ValueError("Superfluid connector is required to create a flow")
        return self.superfluid_connector.create_flow(receiver=receiver, flow=flow)

    def get_flow(self, receiver: str) -> Awaitable[Web3FlowInfo]:
        """Get the Superfluid flow between this account and the receiver address."""
        if not self.superfluid_connector:
            raise ValueError("Superfluid connector is required to get a flow")
        return self.superfluid_connector.get_flow(
            sender=self.get_address(), receiver=receiver
        )

    def update_flow(self, receiver: str, flow: Decimal) -> Awaitable[str]:
        """Update the Superfluid flow between this account and the receiver address."""
        if not self.superfluid_connector:
            raise ValueError("Superfluid connector is required to update a flow")
        return self.superfluid_connector.update_flow(receiver=receiver, flow=flow)

    def delete_flow(self, receiver: str) -> Awaitable[str]:
        """Delete the Superfluid flow between this account and the receiver address."""
        if not self.superfluid_connector:
            raise ValueError("Superfluid connector is required to delete a flow")
        return self.superfluid_connector.delete_flow(receiver=receiver)


def get_fallback_account(
    path: Optional[Path] = None, chain: Optional[Chain] = None
) -> ETHAccount:
    return ETHAccount(private_key=get_fallback_private_key(path=path), chain=chain)


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
):
    """
    Verifies a signature.
    Args:
        signature: The signature to verify. Can be a hex encoded string or bytes.
        public_key: The sender's public key to use for verification. Can be a checksum, hex encoded string or bytes.
        message: The message to verify. Can be an utf-8 string or bytes.
    Raises:
        BadSignatureError: If the signature is invalid.
    """
    if isinstance(signature, str):
        signature = bytes_from_hex(signature)
    if isinstance(public_key, bytes):
        public_key = "0x" + public_key.hex()
    if isinstance(message, bytes):
        message_hash = encode_defunct(primitive=message)
    else:
        message_hash = encode_defunct(text=message)

    try:
        address = Account.recover_message(message_hash, signature=signature)
        if address.casefold() != public_key.casefold():
            raise BadSignatureError
    except (EthBadSignatureError, BadSignatureError) as e:
        raise BadSignatureError from e
