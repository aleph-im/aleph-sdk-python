from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional

from coincurve.keys import PrivateKey
from ecies import decrypt, encrypt

from aleph.sdk.conf import settings


def get_verification_buffer(message: Dict) -> bytes:
    """
    Returns the verification buffer that Aleph nodes use to verify the signature of a message.
    Note:
        The verification buffer is a string of the following format:
        b"{chain}\\n{sender}\\n{type}\\n{item_hash}"
    Args:
        message: Message to get the verification buffer for
    Returns:
        bytes: Verification buffer
    """
    return "{chain}\n{sender}\n{type}\n{item_hash}".format(**message).encode("utf-8")


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

    @abstractmethod
    async def sign_message(self, message: Dict) -> Dict:
        """
        Returns a signed message from an Aleph message.
        Args:
            message: Message to sign
        Returns:
            Dict: Signed message
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

    async def encrypt(self, content: bytes) -> bytes:
        """
        Encrypts a message using the account's public key.
        Args:
            content: Content bytes to encrypt
        Returns:
            bytes: Encrypted content as bytes
        """
        if self.CURVE == "secp256k1":
            value: bytes = encrypt(self.get_public_key(), content)
            return value
        else:
            raise NotImplementedError

    async def decrypt(self, content: bytes) -> bytes:
        """
        Decrypts a message using the account's private key.
        Args:
            content: Content bytes to decrypt
        Returns:
            bytes: Decrypted content as bytes
        """
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
        if not default_key_path.exists():
            # Create a symlink to use this key by default
            default_key_path.symlink_to(path)
    return private_key
