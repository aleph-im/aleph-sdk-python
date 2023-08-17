import json
from pathlib import Path
from typing import Dict, Optional, Union

from aleph_pytezos.crypto.key import Key
from nacl.public import SealedBox
from nacl.signing import SigningKey

from .common import BaseAccount, get_fallback_private_key, get_verification_buffer


class TezosAccount(BaseAccount):
    CHAIN = "TEZOS"
    CURVE = "secp256k1"
    _account: Key

    def __init__(self, private_key: bytes):
        self.private_key = private_key
        self._account = Key.from_secret_exponent(self.private_key)
        self._signing_key = SigningKey(self.private_key)
        self._private_key = self._signing_key.to_curve25519_private_key()

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        message = self._setup_sender(message)

        verif = get_verification_buffer(message)
        signature = await self.sign_raw(verif)
        sig = {
            "publicKey": self.get_public_key(),
            "signature": signature.decode(),
        }

        message["signature"] = json.dumps(sig)
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        return self._account.sign(buffer).encode()

    def get_address(self) -> str:
        return self._account.public_key_hash()

    def get_public_key(self) -> str:
        return self._account.public_key()

    async def encrypt(self, content) -> bytes:
        return SealedBox(self._private_key.public_key).encrypt(content)

    async def decrypt(self, content) -> bytes:
        return SealedBox(self._private_key).decrypt(content)


def get_fallback_account(path: Optional[Path] = None) -> TezosAccount:
    return TezosAccount(private_key=get_fallback_private_key(path=path))


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
) -> bool:
    """
    Verify a signature using the public key (hash) of a tezos account.

    Note: It requires the public key hash (sp, p2, ed-prefix), not the address (tz1, tz2 prefix)!
    Args:
        signature: The signature to verify. Can be a base58 encoded string or bytes.
        public_key: The public key (hash) of the account. Can be a base58 encoded string or bytes.
        message: The message that was signed. Is a sequence of bytes in raw format or hexadecimal notation.
    """
    key = Key.from_encoded_key(public_key)
    try:
        return key.verify(signature, message)
    except ValueError:
        return False
