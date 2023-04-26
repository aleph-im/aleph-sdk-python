import base64
import hashlib
import json
from typing import Union

import ecdsa
from ecdsa.keys import BadSignatureError as ECDSABadSignatureError
from cosmospy._wallet import privkey_to_address, privkey_to_pubkey
from ecies import encrypt

from .common import BaseAccount, get_fallback_private_key, get_verification_buffer
from ..exceptions import BadSignatureError

DEFAULT_HRP = "cosmos"


def get_signable_message(message):
    signable = get_verification_buffer(message).decode("utf-8")
    content_message = {
        "type": "signutil/MsgSignText",
        "value": {
            "message": signable,
            "signer": message["sender"],
        },
    }

    return {
        "chain_id": "signed-message-v1",
        "account_number": str(0),
        "fee": {
            "amount": [],
            "gas": str(0),
        },
        "memo": "",
        "sequence": str(0),
        "msgs": [
            content_message,
        ],
    }


def get_verification_string(message):
    value = get_signable_message(message)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


class CSDKAccount(BaseAccount):
    CHAIN = "CSDK"
    CURVE = "secp256k1"

    def __init__(self, private_key=None, hrp=DEFAULT_HRP):
        self.private_key = private_key
        self.hrp = hrp

    async def sign_message(self, message):
        message = self._setup_sender(message)

        verif = get_verification_string(message)

        privkey = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        signature_compact = privkey.sign_deterministic(
            verif.encode("utf-8"),
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string_canonize,
        )
        signature_base64_str = base64.b64encode(signature_compact).decode("utf-8")
        base64_pubkey = self.get_public_key()

        sig = {
            "signature": signature_base64_str,
            "pub_key": {"type": "tendermint/PubKeySecp256k1", "value": base64_pubkey},
            "account_number": str(0),
            "sequence": str(0),
        }
        message["signature"] = json.dumps(sig)
        return message

    def get_address(self) -> str:
        return privkey_to_address(self.private_key)

    def get_public_key(self) -> str:
        return base64.b64encode(privkey_to_pubkey(self.private_key)).decode("utf-8")

    async def encrypt(self, content: bytes) -> bytes:
        value: bytes = encrypt(
            base64.b64decode(self.get_public_key().encode("utf-8")), content
        )
        return value


def get_fallback_account(hrp=DEFAULT_HRP):
    return CSDKAccount(private_key=get_fallback_private_key(), hrp=hrp)


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
):
    """
    Verifies a signature of a message, return True if verified, false if not.

    Args:
        signature: The signature to verify. Can be a base64 encoded string or bytes.
        public_key: The public key to use for verification. Can be a base64 encoded string or bytes.
        message: The message to verify. Can be a string or bytes.
    """
    if isinstance(signature, str):
        signature = base64.b64decode(signature)
    if isinstance(public_key, str):
        public_key = base64.b64decode(public_key)
    if isinstance(message, str):
        message = message.encode("utf-8")

    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    try:
        if not vk.verify(signature, message, hashfunc=hashlib.sha256):
            raise BadSignatureError
    except (ECDSABadSignatureError, BadSignatureError) as e:
        raise BadSignatureError from e
