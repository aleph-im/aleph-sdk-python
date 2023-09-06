import base64
import hashlib
import json
from typing import Union

import ecdsa
from cosmospy._wallet import privkey_to_address, privkey_to_pubkey

from .common import BaseAccount, get_fallback_private_key, get_verification_buffer

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
        base64_pubkey = base64.b64encode(self.get_public_key().encode()).decode("utf-8")
        signature = await self.sign_raw(verif.encode("utf-8"))

        sig = {
            "signature": signature.decode("utf-8"),
            "pub_key": {"type": "tendermint/PubKeySecp256k1", "value": base64_pubkey},
            "account_number": str(0),
            "sequence": str(0),
        }
        message["signature"] = json.dumps(sig)
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        privkey = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        signature_compact = privkey.sign_deterministic(
            buffer,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string_canonize,
        )
        return base64.b64encode(signature_compact)

    def get_address(self) -> str:
        # WARNING: Fails with OpenSSL >= 3.2.0 due to deprecation of ripemd160
        return privkey_to_address(self.private_key)

    def get_public_key(self) -> str:
        return privkey_to_pubkey(self.private_key).decode()


def get_fallback_account(hrp=DEFAULT_HRP):
    return CSDKAccount(private_key=get_fallback_private_key(), hrp=hrp)


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
) -> bool:
    """TODO: Implement this"""
    raise NotImplementedError("Not implemented yet")
