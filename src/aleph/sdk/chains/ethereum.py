from pathlib import Path
from typing import Dict, Optional

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount

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
