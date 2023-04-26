import base64
import json
from dataclasses import asdict, dataclass

import pytest

from aleph.sdk.chains.cosmos import (
    CSDKAccount,
    get_fallback_account,
    get_verification_string,
    verify_signature,
)
from aleph.sdk.exceptions import BadSignatureError


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


def test_get_fallback_account():
    account: CSDKAccount = get_fallback_account()

    assert account.CHAIN == "CSDK"
    assert account.CURVE == "secp256k1"
    assert account.private_key
    assert account.get_address().startswith("cosmos")


@pytest.mark.asyncio
async def test_CSDKAccount(cosmos_account):
    account = cosmos_account

    message = Message("CSDK", account.get_address(), "SomeType", "ItemHash")
    signed = await account.sign_message(asdict(message))
    assert signed["signature"]
    assert len(signed["signature"]) == 253

    address = account.get_address()
    assert address
    assert type(address) == str
    assert len(address) == 45

    pubkey = account.get_public_key()
    assert type(pubkey) == str
    assert len(pubkey) == 44


@pytest.mark.asyncio
async def test_decrypt_curve25516(cosmos_account):
    assert cosmos_account.CURVE == "secp256k1"
    content = b"SomeContent"

    encrypted = await cosmos_account.encrypt(content)
    assert type(encrypted) == bytes
    decrypted = await cosmos_account.decrypt(encrypted)
    assert type(decrypted) == bytes
    assert content == decrypted


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
    signature_json = json.loads(message["signature"])
    raw_signature = signature_json["signature"]
    public_key = signature_json["pub_key"]["value"]

    verify_signature(raw_signature, public_key, get_verification_string(message))


@pytest.mark.asyncio
async def test_verify_signature_with_forged_signature(cosmos_account):
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
    public_key = json.loads(message["signature"])["pub_key"]["value"]

    forged_signature = base64.b64encode(bytes(64)).decode("utf-8")
    with pytest.raises(BadSignatureError):
        verify_signature(
            forged_signature, public_key, get_verification_string(message)
        )
