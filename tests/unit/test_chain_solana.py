import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import base58
import pytest
from aleph_message.models import Chain
from nacl.signing import VerifyKey

from aleph.sdk.account import detect_chain_from_private_key
from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.solana import SOLAccount, get_fallback_account, verify_signature
from aleph.sdk.exceptions import BadSignatureError
from aleph.sdk.utils import parse_solana_private_key


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


def test_parse_private_key_base58():
    base58_key = "9beEbjn1Md7prQbH9kk9HjTM3npbj1S49BJQpSpYJKvnfATP8Eki9ofaq19tAzpijjV4TyTtibXGBkRjFnmTkiD"
    private_key_bytes = parse_solana_private_key(base58_key)

    assert isinstance(private_key_bytes, bytes)
    assert len(private_key_bytes) == 32

    account = SOLAccount(private_key_bytes)

    assert account.get_address() == "8XnzZVqAD1GUEYjQvsyURG36F7ZEhyDGpvYD68TSkSLy"
    assert detect_chain_from_private_key(base58_key) == Chain.SOL
    assert isinstance(account.get_address(), str)
    assert len(account.get_address()) > 0


def test_parse_private_key_uint8_array():
    uint8_array_key = [
        73,
        6,
        73,
        131,
        134,
        65,
        155,
        206,
        87,
        203,
        226,
        184,
        174,
        66,
        214,
        252,
        201,
        188,
        56,
        102,
        241,
        81,
        21,
        30,
        150,
        55,
        134,
        252,
        138,
        137,
        174,
        163,
        89,
        90,
        53,
        40,
        237,
        153,
        99,
        127,
        220,
        233,
        29,
        48,
        180,
        199,
        18,
        225,
        249,
        163,
        140,
        157,
        201,
        74,
        221,
        176,
        229,
        6,
        182,
        226,
        74,
        243,
        193,
        143,
    ]
    private_key_bytes = parse_solana_private_key(uint8_array_key)

    assert isinstance(private_key_bytes, bytes)
    assert len(private_key_bytes) == 32

    account = SOLAccount(private_key_bytes)

    assert account.get_address() == "71o4nN2BgB8MdD771U5VAPBj8jwufxkYJZwNnCr81VwL"
    assert detect_chain_from_private_key(uint8_array_key) == Chain.SOL
    assert isinstance(account.get_address(), str)
    assert len(account.get_address()) > 0
