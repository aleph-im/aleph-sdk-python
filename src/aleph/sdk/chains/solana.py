import json
from pathlib import Path
from typing import Dict, List, Optional, Union

import base58
from nacl.exceptions import BadSignatureError as NaclBadSignatureError
from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from ..exceptions import BadSignatureError
from .common import BaseAccount, get_fallback_private_key, get_verification_buffer


def encode(item):
    return base58.b58encode(bytes(item)).decode("ascii")


class SOLAccount(BaseAccount):
    CHAIN = "SOL"
    CURVE = "curve25519"
    _signing_key: SigningKey
    _private_key: PrivateKey

    def __init__(self, private_key: bytes):
        self.private_key = parse_private_key(private_key_from_bytes(private_key))
        self._signing_key = SigningKey(self.private_key)
        self._private_key = self._signing_key.to_curve25519_private_key()

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        message = self._setup_sender(message)
        verif = get_verification_buffer(message)
        signature = await self.sign_raw(verif)
        sig = {
            "publicKey": self.get_address(),
            "signature": encode(signature),
        }
        message["signature"] = json.dumps(sig)
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        """Sign a raw buffer."""
        sig = self._signing_key.sign(buffer)
        return sig.signature

    def export_private_key(self) -> str:
        """Export the private key using Phantom format."""
        return base58.b58encode(
            self.private_key + self._signing_key.verify_key.encode()
        ).decode()

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


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
):
    """
    Verifies a signature.
    Args:
        signature: The signature to verify. Can be a base58 encoded string or bytes.
        public_key: The public key to use for verification. Can be a base58 encoded string or bytes.
        message: The message to verify. Can be an utf-8 string or bytes.
    Raises:
        BadSignatureError: If the signature is invalid.!
    """
    if isinstance(signature, str):
        signature = base58.b58decode(signature)
    if isinstance(message, str):
        message = message.encode("utf-8")
    if isinstance(public_key, str):
        public_key = base58.b58decode(public_key)
    try:
        VerifyKey(public_key).verify(message, signature)
    except NaclBadSignatureError as e:
        raise BadSignatureError from e


def private_key_from_bytes(
    private_key_bytes: bytes, output_format: str = "base58"
) -> Union[str, List[int], bytes]:
    """
    Convert a Solana private key in bytes back to different formats (base58 string, uint8 list, or raw bytes).

    - For base58 string: Encode the bytes into a base58 string.
    - For uint8 list: Convert the bytes into a list of integers.
    - For raw bytes: Return as-is.

    Args:
        private_key_bytes (bytes): The private key in byte format.
        output_format (str): The format to return ('base58', 'list', 'bytes').

    Returns:
        The private key in the requested format.

    Raises:
        ValueError: If the output_format is not recognized or the private key length is invalid.
    """
    if not isinstance(private_key_bytes, bytes):
        raise ValueError("Expected the private key in bytes.")

    if len(private_key_bytes) != 32:
        raise ValueError("Solana private key must be exactly 32 bytes long.")

    if output_format == "base58":
        return base58.b58encode(private_key_bytes).decode("utf-8")

    elif output_format == "list":
        return list(private_key_bytes)

    elif output_format == "bytes":
        return private_key_bytes

    else:
        raise ValueError("Invalid output format. Choose 'base58', 'list', or 'bytes'.")


def parse_private_key(private_key: Union[str, List[int], bytes]) -> bytes:
    """
    Parse the private key which could be either:
    - a base58-encoded string (which may contain both private and public key)
    - a list of uint8 integers (which may contain both private and public key)
    - a byte array (exactly 32 bytes)

    Returns:
        bytes: The private key in byte format (32 bytes).

    Raises:
        ValueError: If the private key format is invalid or the length is incorrect.
    """
    # If the private key is already in byte format
    if isinstance(private_key, bytes):
        if len(private_key) != 32:
            raise ValueError("The private key in bytes must be exactly 32 bytes long.")
        return private_key

    # If the private key is a base58-encoded string
    elif isinstance(private_key, str):
        try:
            decoded_key = base58.b58decode(private_key)
            if len(decoded_key) not in [32, 64]:
                raise ValueError(
                    "The base58 decoded private key must be either 32 or 64 bytes long."
                )
            return decoded_key[:32]
        except Exception as e:
            raise ValueError(f"Invalid base58 encoded private key: {e}")

    # If the private key is a list of uint8 integers
    elif isinstance(private_key, list):
        if all(isinstance(i, int) and 0 <= i <= 255 for i in private_key):
            byte_key = bytes(private_key)
            if len(byte_key) < 32:
                raise ValueError("The uint8 array must contain at least 32 elements.")
            return byte_key[:32]  # Take the first 32 bytes (private key)
        else:
            raise ValueError(
                "Invalid uint8 array, must contain integers between 0 and 255."
            )

    else:
        raise ValueError(
            "Unsupported private key format. Must be a base58 string, bytes, or a list of uint8 integers."
        )
