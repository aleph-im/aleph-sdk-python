import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.substrate import (
    get_fallback_account,
    verify_signature,
    verify_signature_with_ss58_address,
)
from aleph.sdk.exceptions import BadSignatureError


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


def test_get_fallback_account():
    with NamedTemporaryFile() as private_key_file:
        account = get_fallback_account(path=Path(private_key_file.name))
        assert account.CHAIN == "DOT"
        assert account.CURVE == "sr25519"
        assert account._account.ss58_address


@pytest.mark.asyncio
async def test_DOTAccount(substrate_account):
    account = substrate_account

    message = Message("DOT", account.get_address(), "SomeType", "ItemHash")
    signed = await account.sign_message(asdict(message))
    assert signed["signature"]
    assert len(signed["signature"]) == 160

    address = account.get_address()
    assert address
    assert isinstance(address, str)
    assert len(address) == 48

    pubkey = account.get_public_key()
    assert isinstance(pubkey, str)
    assert len(pubkey) == 66


@pytest.mark.asyncio
async def test_verify_signature(substrate_account):
    account = substrate_account

    message = asdict(
        Message(
            "DOT",
            account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await account.sign_message(message)
    assert message["signature"]
    signature = json.loads(message["signature"])["data"]

    verify_signature_with_ss58_address(
        signature, message["sender"], get_verification_buffer(message)
    )

    verify_signature_with_ss58_address(
        signature,
        message["sender"],
        get_verification_buffer(message).decode(),
    )

    verify_signature(
        signature, account.get_public_key(), get_verification_buffer(message)
    )
    verify_signature(
        signature,
        bytes.fromhex(account.get_public_key()[2:]),
        get_verification_buffer(message),
    )


@pytest.mark.asyncio
async def test_verify_signature_with_forged_signature(substrate_account):
    account = substrate_account

    message = asdict(
        Message(
            "DOT",
            account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await account.sign_message(message)
    assert message["signature"]

    forged_signature = "deadbeef" * 16

    with pytest.raises(BadSignatureError):
        verify_signature_with_ss58_address(
            forged_signature, message["sender"], get_verification_buffer(message)
        )


@pytest.mark.asyncio
async def test_verify_signature_wrong_public_key(substrate_account):
    account = substrate_account

    message = asdict(
        Message(
            "DOT",
            account.get_address(),
            "POST",
            "SomeHash",
        )
    )

    await account.sign_message(message)
    assert message["signature"]
    sig = json.loads(message["signature"])

    wrong_public_key: str = "0x" + "0" * 64
    with pytest.raises(BadSignatureError):
        verify_signature(
            sig["data"], wrong_public_key, get_verification_buffer(message)
        )


@pytest.mark.asyncio
async def test_sign_raw(substrate_account):
    buffer = b"SomeBuffer"
    signature = await substrate_account.sign_raw(buffer)
    assert signature
    assert isinstance(signature, bytes)

    verify_signature(signature, substrate_account.get_public_key(), buffer)
    verify_signature_with_ss58_address(
        signature, substrate_account.get_address(), buffer
    )
