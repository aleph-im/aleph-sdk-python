import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import base58
import pytest
from nacl.signing import VerifyKey

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.sol import SOLAccount, get_fallback_account, verify_signature
from aleph.sdk.exceptions import BadSignatureError


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


def test_get_fallback_account():
    with NamedTemporaryFile() as private_key_file:
        account: SOLAccount = get_fallback_account(path=Path(private_key_file.name))

        assert account.CHAIN == "SOL"
        assert account.CURVE == "curve25519"
        assert account._signing_key.verify_key
        assert type(account.private_key) == bytes
        assert len(account.private_key) == 32


@pytest.mark.asyncio
async def test_SOLAccount(solana_account):
    message = asdict(
        Message("SOL", solana_account.get_address(), "SomeType", "ItemHash")
    )
    initial_message = message.copy()
    await solana_account.sign_message(message)
    assert message["signature"]

    address = message["sender"]
    assert address
    assert type(address) == str
    # assert len(address) == 44  # can also be 43?
    signature = json.loads(message["signature"])

    pubkey = base58.b58decode(signature["publicKey"])
    assert type(pubkey) == bytes
    assert len(pubkey) == 32

    verify_key = VerifyKey(pubkey)
    verification_buffer = get_verification_buffer(message)
    assert get_verification_buffer(initial_message) == verification_buffer
    verif = verify_key.verify(
        verification_buffer, signature=base58.b58decode(signature["signature"])
    )

    assert verif == verification_buffer
    assert message["sender"] == signature["publicKey"]

    pubkey = solana_account.get_public_key()
    assert type(pubkey) == str
    assert len(pubkey) == 64


@pytest.mark.asyncio
async def test_decrypt_curve25516(solana_account):
    assert solana_account.CURVE == "curve25519"
    content = b"SomeContent"

    encrypted = await solana_account.encrypt(content)
    assert type(encrypted) == bytes
    decrypted = await solana_account.decrypt(encrypted)
    assert type(decrypted) == bytes
    assert content == decrypted


@pytest.mark.asyncio
async def test_verify_signature(solana_account):
    message = asdict(
        Message(
            "SOL",
            solana_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await solana_account.sign_message(message)
    assert message["signature"]
    raw_signature = json.loads(message["signature"])["signature"]
    assert type(raw_signature) == str

    verify_signature(raw_signature, message["sender"], get_verification_buffer(message))

    # as bytes
    verify_signature(
        base58.b58decode(raw_signature),
        base58.b58decode(message["sender"]),
        get_verification_buffer(message).decode("utf-8"),
    )


@pytest.mark.asyncio
async def test_verify_signature_with_forged_signature(solana_account):
    message = asdict(
        Message(
            "SOL",
            solana_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await solana_account.sign_message(message)
    assert message["signature"]
    # create forged 64 bit signature from random bytes
    forged = base58.b58encode(bytes(64)).decode("utf-8")

    with pytest.raises(BadSignatureError):
        verify_signature(forged, message["sender"], get_verification_buffer(message))
