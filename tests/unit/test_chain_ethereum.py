from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.ethereum import get_fallback_account, verify_signature, ETHAccount
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
        assert account.CHAIN == "ETH"
        assert account.CURVE == "secp256k1"
        assert account._account.address


@pytest.mark.asyncio
async def test_ETHAccount(ethereum_account):
    account = ethereum_account

    message = Message("ETH", account.get_address(), "SomeType", "ItemHash")
    signed = await account.sign_message(asdict(message))
    assert signed["signature"]
    assert len(signed["signature"]) == 132

    address = account.get_address()
    assert address
    assert isinstance(address, str)
    assert len(address) == 42

    pubkey = account.get_public_key()
    assert isinstance(pubkey, str)
    assert len(pubkey) == 68


@pytest.mark.asyncio
async def test_verify_signature(ethereum_account):
    account = ethereum_account

    message = asdict(
        Message(
            "ETH",
            account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await account.sign_message(message)
    assert message["signature"]

    verify_signature(
        message["signature"], message["sender"], get_verification_buffer(message)
    )

    # cover all branching options
    verify_signature(
        message["signature"][2:],
        message["sender"],
        get_verification_buffer(message),
    )
    verify_signature(
        message["signature"],
        bytes.fromhex(message["sender"][2:]),
        get_verification_buffer(message).decode("utf-8"),
    )
    verify_signature(
        message["signature"],
        message["sender"],
        get_verification_buffer(message),
    )


@pytest.mark.asyncio
async def test_verify_signature_with_processed_message(ethereum_account, json_messages):
    message = json_messages[1]
    verify_signature(
        message["signature"], message["sender"], get_verification_buffer(message)
    )


@pytest.mark.asyncio
async def test_verify_signature_with_forged_signature(ethereum_account):
    account = ethereum_account

    message = asdict(
        Message(
            "ETH",
            account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await account.sign_message(message)
    assert message["signature"]

    forged_signature = "0x" + "0" * 130
    with pytest.raises(BadSignatureError):
        verify_signature(
            forged_signature, message["sender"], get_verification_buffer(message)
        )


@pytest.mark.asyncio
async def test_decrypt_secp256k1(ethereum_account):
    account = ethereum_account

    assert account.CURVE == "secp256k1"
    content = b"SomeContent"

    encrypted = await account.encrypt(content)
    assert isinstance(encrypted, bytes)
    decrypted = await account.decrypt(encrypted)
    assert isinstance(decrypted, bytes)
    assert content == decrypted


@pytest.mark.asyncio
async def test_verify_signature_wrong_public_key(ethereum_account):
    account = ethereum_account

    message = asdict(
        Message(
            "ETH",
            account.get_address(),
            "POST",
            "SomeHash",
        )
    )

    await account.sign_message(message)
    assert message["signature"]

    wrong_public_key: str = "0x" + "0" * 130
    with pytest.raises(BadSignatureError):
        verify_signature(
            message["signature"], wrong_public_key, get_verification_buffer(message)
        )


@pytest.mark.asyncio
async def test_sign_raw(ethereum_account):
    buffer = b"SomeBuffer"
    signature = await ethereum_account.sign_raw(buffer)
    assert signature
    assert isinstance(signature, bytes)

    verify_signature(signature, ethereum_account.get_address(), buffer)


def test_from_mnemonic():
    mnemonic = (
        "indoor dish desk flag debris potato excuse depart ticket judge file exit"
    )
    account = ETHAccount.from_mnemonic(mnemonic)
    assert (
        account.get_public_key()
        == "0x0226cc24348fbe0c2912fbb0aa4408e089bb0ae488a88ac46bb13290629a737646"
    )
