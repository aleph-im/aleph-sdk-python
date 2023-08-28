import json
import logging
from pathlib import Path
from typing import Optional, Union

from sr25519 import verify
from substrateinterface import Keypair
from substrateinterface.utils.ss58 import ss58_decode

from ..conf import settings
from ..exceptions import BadSignatureError
from .common import BaseAccount, bytes_from_hex, get_verification_buffer

logger = logging.getLogger(__name__)


class DOTAccount(BaseAccount):
    CHAIN = "DOT"
    CURVE = "sr25519"

    def __init__(self, mnemonics: str, address_type=42):
        self.mnemonics = mnemonics
        self.address_type = address_type
        self._account = Keypair.create_from_mnemonic(
            self.mnemonics, ss58_format=address_type
        )

    async def sign_message(self, message):
        message = self._setup_sender(message)
        verif = get_verification_buffer(message).decode("utf-8")
        signature = await self.sign_raw(verif.encode("utf-8"))
        sig = {"curve": self.CURVE, "data": signature.hex()}
        message["signature"] = json.dumps(sig)
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        return self._account.sign(buffer)

    def get_address(self) -> str:
        return self._account.ss58_address

    def get_public_key(self) -> str:
        return "0x" + self._account.public_key.hex()


def get_fallback_account(path: Optional[Path] = None) -> DOTAccount:
    return DOTAccount(mnemonics=get_fallback_mnemonics(path))


def get_fallback_mnemonics(path: Optional[Path] = None) -> str:
    path = path or settings.PRIVATE_MNEMONIC_FILE
    if path.exists() and path.stat().st_size > 0:
        mnemonic = path.read_text()
    else:
        mnemonic = Keypair.generate_mnemonic()
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(mnemonic)
        default_mnemonic_path = path.parent / "default.mnemonic"

        # If the symlink exists but does not point to a file, delete it.
        if (
            default_mnemonic_path.is_symlink()
            and not default_mnemonic_path.resolve().exists()
        ):
            default_mnemonic_path.unlink()
            logger.warning("The symlink to the mnemonic is broken")

        # Create a symlink to use this mnemonic by default
        if not default_mnemonic_path.exists():
            default_mnemonic_path.symlink_to(path)

    return mnemonic


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
) -> None:
    if isinstance(signature, str):
        signature = bytes_from_hex(signature)
    if isinstance(public_key, str):
        public_key = bytes_from_hex(public_key)
    if isinstance(message, str):
        message = message.encode()

    try:
        # Another attempt with the data wrapped, as discussed in https://github.com/polkadot-js/extension/pull/743
        if not verify(signature, message, public_key) or verify(
            signature, b"<Bytes>" + message + b"</Bytes>", public_key
        ):
            raise BadSignatureError
    except Exception as e:
        raise BadSignatureError from e


def verify_signature_with_ss58_address(
    signature: Union[bytes, str], address: str, message: Union[bytes, str]
) -> None:
    address_bytes = ss58_decode(address)
    return verify_signature(signature, address_bytes, message)
