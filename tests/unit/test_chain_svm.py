import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import base58
import pytest
from aleph_message.models import Chain
from nacl.signing import VerifyKey

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.solana import get_fallback_account as get_solana_account
from aleph.sdk.chains.solana import verify_signature
from aleph.sdk.chains.svm import SVMAccount
from aleph.sdk.exceptions import BadSignatureError


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


@pytest.fixture
def svm_account() -> SVMAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        solana_account = get_solana_account(path=Path(private_key_file.name))
        return SVMAccount(private_key=solana_account.private_key)


@pytest.fixture
def svm_eclipse_account() -> SVMAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        solana_account = get_solana_account(path=Path(private_key_file.name))
        return SVMAccount(private_key=solana_account.private_key, chain=Chain.ECLIPSE)


def test_svm_account_init():
    with NamedTemporaryFile() as private_key_file:
        solana_account = get_solana_account(path=Path(private_key_file.name))
        account = SVMAccount(private_key=solana_account.private_key)

        # Default chain should be SOL
        assert account.CHAIN == Chain.SOL
        assert account.CURVE == "curve25519"
        assert account._signing_key.verify_key
        assert isinstance(account.private_key, bytes)
        assert len(account.private_key) == 32

        # Test with custom chain
        account_eclipse = SVMAccount(
            private_key=solana_account.private_key, chain=Chain.ECLIPSE
        )
        assert account_eclipse.CHAIN == Chain.ECLIPSE


@pytest.mark.asyncio
async def test_svm_sign_message(svm_account):
    message = asdict(Message("ES", svm_account.get_address(), "SomeType", "ItemHash"))
    initial_message = message.copy()
    await svm_account.sign_message(message)
    assert message["signature"]

    address = message["sender"]
    assert address
    assert isinstance(address, str)
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

    pubkey = svm_account.get_public_key()
    assert isinstance(pubkey, str)
    assert len(pubkey) == 64


@pytest.mark.asyncio
async def test_svm_custom_chain_sign_message(svm_eclipse_account):
    message = asdict(
        Message(
            Chain.ECLIPSE, svm_eclipse_account.get_address(), "SomeType", "ItemHash"
        )
    )
    await svm_eclipse_account.sign_message(message)
    assert message["signature"]

    # Verify message has correct chain
    assert message["chain"] == Chain.ECLIPSE

    # Rest of verification is the same
    signature = json.loads(message["signature"])
    pubkey = base58.b58decode(signature["publicKey"])
    verify_key = VerifyKey(pubkey)
    verification_buffer = get_verification_buffer(message)
    verif = verify_key.verify(
        verification_buffer, signature=base58.b58decode(signature["signature"])
    )
    assert verif == verification_buffer


@pytest.mark.asyncio
async def test_svm_decrypt(svm_account):
    assert svm_account.CURVE == "curve25519"
    content = b"SomeContent"

    encrypted = await svm_account.encrypt(content)
    assert isinstance(encrypted, bytes)
    decrypted = await svm_account.decrypt(encrypted)
    assert isinstance(decrypted, bytes)
    assert content == decrypted


@pytest.mark.asyncio
async def test_svm_verify_signature(svm_account):
    message = asdict(
        Message(
            "SVM",
            svm_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await svm_account.sign_message(message)
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
async def test_verify_signature_with_forged_signature(svm_account):
    message = asdict(
        Message(
            "SVM",
            svm_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await svm_account.sign_message(message)
    assert message["signature"]
    # create forged 64 bit signature from random bytes
    forged = base58.b58encode(bytes(64)).decode("utf-8")

    with pytest.raises(BadSignatureError):
        verify_signature(forged, message["sender"], get_verification_buffer(message))


@pytest.mark.asyncio
async def test_svm_sign_raw(svm_account):
    buffer = b"SomeBuffer"
    signature = await svm_account.sign_raw(buffer)
    assert signature
    assert isinstance(signature, bytes)

    verify_signature(signature, svm_account.get_address(), buffer)


def test_svm_with_various_chain_values():
    # Test with different chain formats
    with NamedTemporaryFile() as private_key_file:
        solana_account = get_solana_account(path=Path(private_key_file.name))

        # Test with string
        account1 = SVMAccount(private_key=solana_account.private_key, chain="ES")
        assert account1.CHAIN == Chain.ECLIPSE

        # Test with Chain enum if it exists
        account2 = SVMAccount(
            private_key=solana_account.private_key, chain=Chain.ECLIPSE
        )
        assert account2.CHAIN == Chain.ECLIPSE

        # Test default
        account3 = SVMAccount(private_key=solana_account.private_key)
        assert account3.CHAIN == Chain.SOL
