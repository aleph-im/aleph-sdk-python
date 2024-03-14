import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional

from coincurve.keys import PrivateKey
from typing_extensions import deprecated

from aleph.sdk.conf import settings
from aleph.sdk.utils import enum_as_str

logger = logging.getLogger(__name__)


def get_verification_buffer(message: Dict) -> bytes:
    """
    Returns the verification buffer that aleph.im nodes use to verify the signature of a message.
    Note:
        The verification buffer is a string of the following format:
        b"{chain}\\n{sender}\\n{type}\\n{item_hash}"
    Args:
        message: Message to get the verification buffer for
    Returns:
        bytes: Verification buffer
    """

    # Convert Enum values to strings
    return "\n".join(
        (
            enum_as_str(message["chain"]) or "",
            message["sender"],
            enum_as_str(message["type"]) or "",
            message["item_hash"],
        )
    ).encode()


def get_public_key(private_key):
    privkey = PrivateKey(private_key)
    return privkey.public_key.format()


class BaseAccount(ABC):
    CHAIN: str
    CURVE: str
    private_key: bytes

    def _setup_sender(self, message: Dict) -> Dict:
        """
        Set the sender of the message as the account's public key.
        If a sender is already specified, check that it matches the account's public key.
        Args:
            message: Message to add the sender to
        Returns:
            Dict: Message with the sender set
        """
        if not message.get("sender"):
            message["sender"] = self.get_address()
            return message
        elif message["sender"] == self.get_address():
            return message
        else:
            raise ValueError("Message sender does not match the account's public key.")

    async def sign_message(self, message: Dict) -> Dict:
        """
        Returns a signed message from an aleph.im message.
        Args:
            message: Message to sign
        Returns:
            Dict: Signed message
        """
        message = self._setup_sender(message)
        signature = await self.sign_raw(get_verification_buffer(message))
        message["signature"] = signature.hex()
        return message

    @abstractmethod
    async def sign_raw(self, buffer: bytes) -> bytes:
        """
        Returns a signed message from a raw buffer.
        Args:
            buffer: Buffer to sign
        Returns:
            bytes: Signature in preferred format
        """
        raise NotImplementedError

    @abstractmethod
    def get_address(self) -> str:
        """
        Returns the account's displayed address.
        """
        raise NotImplementedError

    @abstractmethod
    def get_public_key(self) -> str:
        """
        Returns the account's public key.
        """
        raise NotImplementedError

    @deprecated("This method will be moved to its own module `aleph.sdk.encryption`")
    async def encrypt(self, content: bytes) -> bytes:
        """
        Encrypts a message using the account's public key.
        Args:
            content: Content bytes to encrypt
        Returns:
            bytes: Encrypted content as bytes
        """
        try:
            from ecies import encrypt
        except ImportError:
            raise ImportError(
                "Install `eciespy` or `aleph-sdk-python[encryption]` to use this method"
            )
        if self.CURVE == "secp256k1":
            value: bytes = encrypt(self.get_public_key(), content)
            return value
        else:
            raise NotImplementedError

    @deprecated("This method will be moved to its own module `aleph.sdk.encryption`")
    async def decrypt(self, content: bytes) -> bytes:
        """
        Decrypts a message using the account's private key.
        Args:
            content: Content bytes to decrypt
        Returns:
            bytes: Decrypted content as bytes
        """
        try:
            from ecies import decrypt
        except ImportError:
            raise ImportError(
                "Install `eciespy` or `aleph-sdk-python[encryption]` to use this method"
            )
        if self.CURVE == "secp256k1":
            value: bytes = decrypt(self.private_key, content)
            return value
        else:
            raise NotImplementedError


# Start of the ugly stuff
def generate_key() -> bytes:
    privkey = PrivateKey()
    return privkey.secret


def get_fallback_private_key(path: Optional[Path] = None) -> bytes:
    path = path or settings.PRIVATE_KEY_FILE
    private_key: bytes
    if path.exists() and path.stat().st_size > 0:
        private_key = path.read_bytes()
    else:
        private_key = generate_key()
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(private_key)

        default_key_path = path.parent / "default.key"

        # If the symlink exists but does not point to a file, delete it.
        if default_key_path.is_symlink() and not default_key_path.resolve().exists():
            default_key_path.unlink()
            logger.warning("The symlink to the private key is broken")

        # Create a symlink to use this key by default
        if not default_key_path.exists():
            default_key_path.symlink_to(path)
    return private_key


def bytes_from_hex(hex_string: str) -> bytes:
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    hex_string = bytes.fromhex(hex_string)
    return hex_string
