from pathlib import Path
from typing import Dict, Optional, Union

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from eth_keys.exceptions import BadSignature as EthBadSignatureError

from ..exceptions import BadSignatureError
from .common import (
    BaseAccount,
    get_fallback_private_key,
    get_public_key,
    get_verification_buffer,
)


class ETHAccount(BaseAccount):
    CHAIN = "ETH"
    CURVE = "secp256k1"
    _account: LocalAccount

    def __init__(self, private_key: bytes):
        self.private_key = private_key
        self._account = Account.from_key(self.private_key)

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        message = self._setup_sender(message)

        msghash = encode_defunct(text=get_verification_buffer(message).decode("utf-8"))
        sig = self._account.sign_message(msghash)

        message["signature"] = sig["signature"].hex()
        return message

    def get_address(self) -> str:
        return self._account.address

    def get_public_key(self) -> str:
        return "0x" + get_public_key(private_key=self._account.key).hex()


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
        if signature.startswith("0x"):
            signature = signature[2:]
        signature = bytes.fromhex(signature)
    else:
        if signature.startswith(b"0x"):
            signature = signature[2:]
        signature = bytes.fromhex(signature.decode("utf-8"))
    if isinstance(public_key, bytes):
        public_key = "0x" + public_key.hex()
    if isinstance(message, bytes):
        message = message.decode("utf-8")

    message_hash = encode_defunct(text=message)
    try:
        address = Account.recover_message(message_hash, signature=signature)
        if address.casefold() != public_key.casefold():
            raise BadSignatureError
    except (EthBadSignatureError, BadSignatureError) as e:
        raise BadSignatureError from e
