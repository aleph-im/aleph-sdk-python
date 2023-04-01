import json
import os
from pathlib import Path
from typing import Dict, Optional, Union

import base58
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from ..conf import settings
from .common import BaseAccount, get_verification_buffer


def encode(item):
    return base58.b58encode(bytes(item)).decode("ascii")


class SOLAccount(BaseAccount):
    CHAIN = "SOL"
    CURVE = "curve25519"
    _signing_key: SigningKey
    _private_key: PrivateKey

    def __init__(self, private_key: bytes):
        self.private_key = private_key
        self._signing_key = SigningKey(self.private_key)
        self._private_key = self._signing_key.to_curve25519_private_key()

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        message = self._setup_sender(message)
        verif = get_verification_buffer(message)
        sig = {
            "publicKey": self.get_address(),
            "signature": encode(self._signing_key.sign(verif).signature),
        }
        message["signature"] = json.dumps(sig)
        return message

    def get_address(self) -> str:
        return encode(self._signing_key.verify_key)

    def get_public_key(self) -> str:
        return bytes(self._signing_key.verify_key.to_curve25519_public_key()).hex()

    async def encrypt(self, content) -> bytes:
        value: bytes = bytes(SealedBox(self._private_key.public_key).encrypt(content))
        return value

    async def decrypt(self, content) -> bytes:
        value: bytes = SealedBox(self._private_key).decrypt(content)
        return value


def get_fallback_account(path: Optional[Path] = None) -> SOLAccount:
    return SOLAccount(private_key=get_fallback_private_key(path=path))


def generate_key() -> bytes:
    privkey = bytes(SigningKey.generate())
    return privkey


def get_fallback_private_key(path: Optional[Path] = None) -> bytes:
    path = path or settings.PRIVATE_KEY_FILE
    private_key: bytes
    if path.exists() and path.stat().st_size > 0:
        with open(path, "rb") as prvfile:
            private_key = prvfile.read()
    else:
        private_key = generate_key()
        os.makedirs(path.parent, exist_ok=True)
        with open(path, "wb") as prvfile:
            prvfile.write(private_key)

        with open(path, "rb") as prvfile:
            print(prvfile.read())

        default_key_path = path.parent / "default.key"
        if not default_key_path.is_symlink():
            # Create a symlink to use this key by default
            os.symlink(path, default_key_path)
    return private_key


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
) -> bool:
    """
    Verifies a signature.
    Args:
        signature: The signature to verify. Can be a base58 encoded string or bytes.
        public_key: The public key to use for verification. Can be a base58 encoded string or bytes.
        message: The message to verify. Can be an utf-8 string or bytes.
    """
    if isinstance(signature, str):
        signature = base58.b58decode(signature)
    if isinstance(message, str):
        message = message.encode("utf-8")
    if isinstance(public_key, str):
        public_key = base58.b58decode(public_key)
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except BadSignatureError:
        return False
