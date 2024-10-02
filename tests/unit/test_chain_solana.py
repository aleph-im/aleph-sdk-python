import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import base58
import pytest
from nacl.signing import VerifyKey

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.solana import (
    SOLAccount,
    get_fallback_account,
    parse_private_key,
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
    with NamedTemporaryFile() as private_key_file:
        account: SOLAccount = get_fallback_account(path=Path(private_key_file.name))

        assert account.CHAIN == "SOL"
        assert account.CURVE == "curve25519"
        assert account._signing_key.verify_key
        assert isinstance(account.private_key, bytes)
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
    assert isinstance(address, str)
    # assert len(address) == 44  # can also be 43?
    signature = json.loads(message["signature"])

    pubkey = base58.b58decode(signature["publicKey"])
    assert isinstance(pubkey, bytes)
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
    assert isinstance(pubkey, str)
    assert len(pubkey) == 64


@pytest.mark.asyncio
async def test_decrypt_curve25516(solana_account):
    assert solana_account.CURVE == "curve25519"
    content = b"SomeContent"

    encrypted = await solana_account.encrypt(content)
    assert isinstance(encrypted, bytes)
    decrypted = await solana_account.decrypt(encrypted)
    assert isinstance(decrypted, bytes)
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
    assert isinstance(raw_signature, str)

    verify_signature(raw_signature, message["sender"], get_verification_buffer(message))

    # as bytes
    verify_signature(
        base58.b58decode(raw_signature),
        base58.b58decode(message["sender"]),
        get_verification_buffer(message).decode("utf-8"),
    )


@pytest.mark.asyncio
async def test_verify_signature_with_processed_message(solana_account, json_messages):
    message = json_messages[0]
    signature = json.loads(message["signature"])["signature"]
    verify_signature(signature, message["sender"], get_verification_buffer(message))


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


@pytest.mark.asyncio
async def test_sign_raw(solana_account):
    buffer = b"SomeBuffer"
    signature = await solana_account.sign_raw(buffer)
    assert signature
    assert isinstance(signature, bytes)

    verify_signature(signature, solana_account.get_address(), buffer)


def test_parse_solana_private_key_bytes():
    # Valid 32-byte private key
    private_key_bytes = bytes(range(32))
    parsed_key = parse_private_key(private_key_bytes)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32
    assert parsed_key == private_key_bytes

    # Invalid private key (too short)
    with pytest.raises(
        ValueError, match="The private key in bytes must be exactly 32 bytes long."
    ):
        parse_private_key(bytes(range(31)))


def test_parse_solana_private_key_base58():
    # Valid base58 private key (32 bytes)
    base58_key = base58.b58encode(bytes(range(32))).decode("utf-8")
    parsed_key = parse_private_key(base58_key)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32

    # Invalid base58 key (not decodable)
    with pytest.raises(ValueError, match="Invalid base58 encoded private key"):
        parse_private_key("invalid_base58_key")

    # Invalid base58 key (wrong length)
    with pytest.raises(
        ValueError,
        match="The base58 decoded private key must be either 32 or 64 bytes long.",
    ):
        parse_private_key(base58.b58encode(bytes(range(31))).decode("utf-8"))


def test_parse_solana_private_key_list():
    # Valid list of uint8 integers (64 elements, but we only take the first 32 for private key)
    uint8_list = list(range(64))
    parsed_key = parse_private_key(uint8_list)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32
    assert parsed_key == bytes(range(32))

    # Invalid list (contains non-integers)
    with pytest.raises(ValueError, match="Invalid uint8 array"):
        parse_private_key([1, 2, "not an int", 4])  # type: ignore  # Ignore type check for string

    # Invalid list (less than 32 elements)
    with pytest.raises(
        ValueError, match="The uint8 array must contain at least 32 elements."
    ):
        parse_private_key(list(range(31)))
