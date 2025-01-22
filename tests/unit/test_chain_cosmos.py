import base64
import json
from dataclasses import asdict, dataclass

import pytest
from ecdsa import BadSignatureError

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.cosmos import get_verification_string, verify_signature


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


@pytest.mark.asyncio
async def test_verify_signature(cosmos_account):
    message = asdict(
        Message(
            "CSDK",
            cosmos_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await cosmos_account.sign_message(message)
    assert message["signature"]
    signature = json.loads(message["signature"])
    raw_signature = signature["signature"]
    assert isinstance(raw_signature, str)

    pub_key = base64.b64decode(signature["pub_key"]["value"])

    verify_signature(
        raw_signature,
        pub_key,
        get_verification_string(message),
    )


@pytest.mark.asyncio
async def test_verify_signature_raw(cosmos_account):
    message = asdict(
        Message(
            "CSDK",
            cosmos_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await cosmos_account.sign_message(message)
    raw_message = get_verification_buffer(message)
    raw_signature = await cosmos_account.sign_raw(raw_message)
    assert isinstance(raw_signature, bytes)

    pub_key = cosmos_account.get_public_key()
    verify_signature(
        raw_signature.decode(),
        pub_key,
        raw_message,
    )


@pytest.mark.asyncio
async def test_bad_signature(cosmos_account):
    message = asdict(
        Message(
            "CSDK",
            cosmos_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await cosmos_account.sign_message(message)
    assert message["signature"]
    signature = json.loads(message["signature"])
    raw_signature = "1" + signature["signature"]
    assert isinstance(raw_signature, str)

    pub_key = base64.b64decode(signature["pub_key"]["value"])

    with pytest.raises(BadSignatureError):
        verify_signature(
            raw_signature,
            pub_key,
            get_verification_string(message),
        )
