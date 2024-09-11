import json
import logging
import sys
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

from coincurve.keys import PrivateKey
from rich.prompt import Console, Prompt, Text
from typing_extensions import deprecated
from web3 import Web3

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


def generate_key() -> bytes:
    """
    Generate a new private key.

    Returns:
    bytes: The generated private key as bytes.
    """

    privkey = PrivateKey()
    return privkey.secret


def create_or_import_key() -> bytes:
    """
    Create or import a private key.

    This function allows the user to either import an existing private key
    or generate a new one. If the user chooses to import a key, they can
    enter a private key in hexadecimal format or a mnemonic seed phrase.

    Returns:
    bytes: The private key as bytes.
    """
    if Prompt.ask("Import an existing wallet", choices=["y", "n"], default="n") == "y":
        data = Prompt.ask("Enter your private key or mnemonic seed phrase")
        # private key
        if data.startswith("0x"):
            data = data[2:]
        if len(data) == 64:
            return bytes.fromhex(data)
        # mnemonic seed phrase
        elif len(data.split()) in [12, 24]:
            w3 = Web3()
            w3.eth.account.enable_unaudited_hdwallet_features()
            return w3.eth.account.from_mnemonic(data.strip()).key
        else:
            raise ValueError("Invalid private key or mnemonic seed phrase")
    else:
        return generate_key()


def save_key(private_key: bytes, path: Path):
    """
    Save a private key to a file.

    Parameters:
    private_key (bytes): The private key as bytes.
    path (Path): The path to the private key file.

    Returns:
    None
    """
    w3 = Web3()
    address = None
    path.parent.mkdir(exist_ok=True, parents=True)
    if path.name.endswith(".key") or "pytest" in sys.modules:
        address = w3.to_checksum_address(w3.eth.account.from_key(private_key).address)
        path.write_bytes(private_key)
    elif path.name.endswith(".json"):
        address = w3.to_checksum_address(w3.eth.account.from_key(private_key).address)
        password = Prompt.ask(
            "Enter a password to encrypt your keystore", password=True
        )
        keystore = w3.eth.account.encrypt(private_key, password)
        path.write_text(json.dumps(keystore))
    else:
        raise ValueError("Unsupported private key file format")
    confirmation = Text.assemble(
        "\nYour address: ",
        Text(address, style="cyan"),
        "\nSaved file: ",
        Text(str(path), style="orange1"),
        "\n",
    )
    Console().print(confirmation)


@lru_cache(maxsize=1)
def load_key(private_key_path: Path) -> bytes:
    """
    Load a private key from a file.

    This function supports two types of private key files:
    1. Unencrypted .key files.
    2. Encrypted .json keystore files.

    Parameters:
    private_key_path (Path): The path to the private key file.

    Returns:
    bytes: The private key as bytes.

    Raises:
    FileNotFoundError: If the private key file does not exist.
    ValueError: If the private key file is not a .key or .json file.
    """
    if not private_key_path.exists():
        raise FileNotFoundError("Private key file not found")
    elif private_key_path.name.endswith(".key"):
        return private_key_path.read_bytes()
    elif private_key_path.name.endswith(".json"):
        keystore = private_key_path.read_text()
        password = Prompt.ask("Keystore password", password=True)
        try:
            return Web3().eth.account.decrypt(keystore, password)
        except ValueError:
            raise ValueError("Invalid password")
    else:
        raise ValueError("Unsupported private key file format")


def get_fallback_private_key(path: Optional[Path] = None) -> bytes:
    """
    Retrieve or create a fallback private key.

    This function attempts to load a private key from the specified path.
    If the path is not provided, it defaults to the path specified in the
    settings. If the file does not exist or is empty, a new private key
    is generated and saved to the specified path. A symlink is also created
    to use this key by default.

    Parameters:
    path (Optional[Path]): The path to the private key file. If not provided,
                           the default path from settings is used.

    Returns:
    bytes: The private key as bytes.
    """
    path = path or settings.PRIVATE_KEY_FILE
    private_key: bytes
    if path.exists() and path.stat().st_size > 0:
        private_key = load_key(path)
    else:
        private_key = (
            generate_key()
            if path.name.endswith(".key") or "pytest" in sys.modules
            else create_or_import_key()
        )
        save_key(private_key, path)
        default_key_path = path.parent / "default.key"

        # If the symlink exists but does not point to a file, delete it.
        if default_key_path.is_symlink() and not default_key_path.resolve().exists():
            default_key_path.unlink()
            logger.warning("The symlink to the private key is broken")

        # Create a symlink to use this key by default
        if not default_key_path.exists():
            default_key_path.symlink_to(path)
    return private_key
