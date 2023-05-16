import json
from typing import Union

from substrateinterface import Keypair

from ..conf import settings
from .common import BaseAccount, get_verification_buffer


class DOTAccount(BaseAccount):
    CHAIN = "DOT"
    CURVE = "sr25519"

    def __init__(self, mnemonics=None, address_type=42):
        self.mnemonics = mnemonics
        self.address_type = address_type
        self._account = Keypair.create_from_mnemonic(
            self.mnemonics, address_type=address_type
        )

    async def sign_message(self, message):
        message = self._setup_sender(message)
        verif = get_verification_buffer(message).decode("utf-8")
        sig = {"curve": self.CURVE, "data": self._account.sign(verif)}
        message["signature"] = json.dumps(sig)
        return message

    def get_address(self):
        return self._account.ss58_address

    def get_public_key(self):
        return self._account.public_key


def get_fallback_account():
    return DOTAccount(mnemonics=get_fallback_mnemonics())


def get_fallback_mnemonics():
    try:
        mnemonic = settings.PRIVATE_KEY_FILE.read_text()
    except OSError:
        mnemonic = Keypair.generate_mnemonic()
        settings.PRIVATE_KEY_FILE.write_text(mnemonic)

    return mnemonic


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
) -> bool:
    """TODO: Implement this"""
    raise NotImplementedError("Not implemented yet")
