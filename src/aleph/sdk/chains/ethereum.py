from pathlib import Path
from typing import Optional, Union

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from eth_keys.exceptions import BadSignature as EthBadSignatureError

from ..exceptions import BadSignatureError
from .common import (
    BaseAccount,
    bytes_from_hex,
    get_fallback_private_key,
    get_public_key,
)


class ETHAccount(BaseAccount):
    CHAIN = "ETH"
    CURVE = "secp256k1"
    _account: LocalAccount

    def __init__(self, private_key: bytes):
        self.private_key = private_key
        self._account = Account.from_key(self.private_key)

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
