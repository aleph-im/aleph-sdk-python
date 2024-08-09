from decimal import Decimal
from pathlib import Path
from typing import Awaitable, Dict, Optional, Set, Union

from aleph_message.models import Chain
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from eth_keys.exceptions import BadSignature as EthBadSignatureError
from superfluid import Web3FlowInfo

from ..conf import settings
from ..connectors.superfluid import Superfluid
from ..exceptions import BadSignatureError
from ..utils import bytes_from_hex
from .common import BaseAccount, get_fallback_private_key, get_public_key

CHAINS_WITH_SUPERTOKEN: Set[Chain] = {Chain.AVAX}
CHAIN_IDS: Dict[Chain, int] = {
    Chain.AVAX: settings.AVAX_CHAIN_ID,
}


def get_rpc_for_chain(chain: Chain):
    """Returns the RPC to use for a given Ethereum based blockchain"""
    if not chain:
        return None

    if chain == Chain.AVAX:
        return settings.AVAX_RPC
    else:
        raise ValueError(f"Unknown RPC for chain {chain}")


def get_chain_id_for_chain(chain: Chain):
    """Returns the chain ID of a given Ethereum based blockchain"""
    if not chain:
        return None

    if chain in CHAIN_IDS:
        return CHAIN_IDS[chain]
    else:
        raise ValueError(f"Unknown RPC for chain {chain}")


class ETHAccount(BaseAccount):
    """Interact with an Ethereum address or key pair"""

    CHAIN = "ETH"
    CURVE = "secp256k1"
    _account: LocalAccount
    chain: Optional[Chain]
    superfluid_connector: Optional[Superfluid]

    def __init__(
        self,
        private_key: bytes,
        chain: Optional[Chain] = None,
        rpc: Optional[str] = None,
        chain_id: Optional[int] = None,
    ):
        self.private_key = private_key
        self._account = Account.from_key(self.private_key)
        self.chain = chain
        rpc = rpc or get_rpc_for_chain(chain)
        chain_id = chain_id or get_chain_id_for_chain(chain)
        self.superfluid_connector = (
            Superfluid(
                rpc=rpc,
                chain_id=chain_id,
                account=self._account,
            )
            if chain in CHAINS_WITH_SUPERTOKEN
            else None
        )

    async def sign_raw(self, buffer: bytes) -> bytes:
        """Sign a raw buffer."""
        msghash = encode_defunct(text=buffer.decode("utf-8"))
        sig = self._account.sign_message(msghash)
        return sig["signature"]

    def get_address(self) -> str:
        return self._account.address

    def get_public_key(self) -> str:
        return "0x" + get_public_key(private_key=self._account.key).hex()

    @staticmethod
    def from_mnemonic(mnemonic: str) -> "ETHAccount":
        Account.enable_unaudited_hdwallet_features()
        return ETHAccount(private_key=Account.from_mnemonic(mnemonic=mnemonic).key)

    def create_flow(self, receiver: str, flow: Decimal) -> Awaitable[str]:
        """Creat a Superfluid flow between this account and the receiver address."""
        if not self.superfluid_connector:
            raise ValueError("Superfluid connector is required to create a flow")
        return self.superfluid_connector.create_flow(
            sender=self.get_address(), receiver=receiver, flow=flow
        )

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
        return self.superfluid_connector.update_flow(
            sender=self.get_address(), receiver=receiver, flow=flow
        )

    def delete_flow(self, receiver: str) -> Awaitable[str]:
        """Delete the Superfluid flow between this account and the receiver address."""
        if not self.superfluid_connector:
            raise ValueError("Superfluid connector is required to delete a flow")
        return self.superfluid_connector.delete_flow(
            sender=self.get_address(), receiver=receiver
        )

    def update_superfluid_connector(self, rpc: str, chain_id: int):
        """Update the Superfluid connector after initialisation."""
        self.superfluid_connector = Superfluid(
            rpc=rpc,
            chain_id=chain_id,
            account=self._account,
        )


def get_fallback_account(path: Optional[Path] = None) -> ETHAccount:
    return ETHAccount(private_key=get_fallback_private_key(path=path))


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
