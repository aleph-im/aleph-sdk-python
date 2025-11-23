import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Union

import base58
import pytest
from nacl.signing import VerifyKey

# Assuming these modules are part of the Aleph SDK
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
    """A minimal message structure used for signing and verification tests."""
    chain: str
    sender: str
    type: str
    item_hash: str


def test_get_fallback_account() -> None:
    """
    Tests the creation of a SOLAccount instance using the fallback mechanism,
    which typically generates a new keypair and saves it to a temporary file.
    """
    with NamedTemporaryFile() as private_key_file:
        account: SOLAccount = get_fallback_account(path=Path(private_key_file.name))

        # Assert fundamental characteristics of the generated account
        assert account.CHAIN == "SOL"
        assert account.CURVE == "curve25519"
        # Check if the signing key has a verification key (i.e., it's a valid keypair)
        assert account._signing_key.verify_key
        assert isinstance(account.private_key, bytes)
        # Check that the raw private key (seed) is 32 bytes long
        assert len(account.private_key) == 32


@pytest.mark.asyncio
async def test_SOLAccount(solana_account: SOLAccount) -> None:
    """
    Tests the signing capability of a SOLAccount and verifies the signature
    using raw cryptography tools (PyNaCl).
    """
    # 1. Arrange: Prepare message and signature process
    message: Dict[str, Any] = asdict(
        Message("SOL", solana_account.get_address(), "SomeType", "ItemHash")
    )
    initial_message = message.copy()

    # 2. Act: Sign the message (modifies the message dict in place)
    await solana_account.sign_message(message)
    assert "signature" in message

    # 3. Assert & Verification Checks
    address: str = message["sender"]
    assert isinstance(address, str)

    # Parse the signature object which is stored as a JSON string in the message
    signature_obj: Dict[str, str] = json.loads(message["signature"])

    # Extract the public key from the signature object
    pubkey_base58: str = signature_obj["publicKey"]
    pubkey_bytes: bytes = base58.b58decode(pubkey_base58)
    assert isinstance(pubkey_bytes, bytes)
    assert len(pubkey_bytes) == 32

    # Instantiate the verification key using raw PyNaCl/nacl
    verify_key = VerifyKey(pubkey_bytes)
    
    # Get the canonical buffer that was signed
    verification_buffer: bytes = get_verification_buffer(message)
    # Ensure the verification buffer is based on the unsigned content
    assert get_verification_buffer(initial_message) == verification_buffer

    # Verify the signature against the buffer
    verified_buffer = verify_key.verify(
        verification_buffer, signature=base58.b58decode(signature_obj["signature"])
    )

    # If verification is successful, the returned value is the buffer itself
    assert verified_buffer == verification_buffer
    
    # Sanity check: the sender address in the message must match the public key in the signature
    assert message["sender"] == signature_obj["publicKey"]

    # Check the format of the key returned by the account object (assumed to be hex)
    pubkey_hex: str = solana_account.get_public_key()
    assert isinstance(pubkey_hex, str)
    # A 32-byte key is 64 characters in hexadecimal format
    assert len(pubkey_hex) == 64


@pytest.mark.asyncio
async def test_decrypt_curve25516(solana_account: SOLAccount) -> None:
    """
    Tests the encryption and decryption loop using the Ed25519/curve25519 properties.
    """
    assert solana_account.CURVE == "curve25519"
    content = b"SomeContent"

    # Encrypt
    encrypted: bytes = await solana_account.encrypt(content)
    assert isinstance(encrypted, bytes)
    
    # Decrypt
    decrypted: bytes = await solana_account.decrypt(encrypted)
    assert isinstance(decrypted, bytes)
    
    # Assert original content matches decrypted content
    assert content == decrypted


@pytest.mark.asyncio
async def test_verify_signature(solana_account: SOLAccount) -> None:
    """
    Tests the utility verification function with both string (Base58) and raw byte inputs.
    """
    # 1. Arrange: Sign the message
    message: Dict[str, Any] = asdict(
        Message(
            "SOL",
            solana_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await solana_account.sign_message(message)
    assert "signature" in message
    
    raw_signature_b58: str = json.loads(message["signature"])["signature"]
    assert isinstance(raw_signature_b58, str)
    verification_buffer: bytes = get_verification_buffer(message)

    # 2. Test 1: Verify using Base58 encoded string inputs (standard API usage)
    verify_signature(raw_signature_b58, message["sender"], verification_buffer)

    # 3. Test 2: Verify using raw bytes inputs (for stricter type checks)
    # NOTE: The decode("utf-8") call from the original script is removed here,
    # assuming the verification buffer must be passed as raw bytes.
    verify_signature(
        base58.b58decode(raw_signature_b58),  # signature as bytes
        base58.b58decode(message["sender"]),  # sender (public key) as bytes
        verification_buffer,                  # verification buffer as bytes
    )


@pytest.mark.asyncio
async def test_verify_signature_with_processed_message(solana_account: SOLAccount, json_messages: List[Dict[str, Any]]) -> None:
    """
    Tests signature verification using a pre-processed/fixture message structure.
    """
    # Select the first fixture message
    message: Dict[str, Any] = json_messages[0]
    
    # Extract the Base58 signature string
    signature: str = json.loads(message["signature"])["signature"]
    
    # Perform verification
    verify_signature(signature, message["sender"], get_verification_buffer(message))


@pytest.mark.asyncio
async def test_verify_signature_with_forged_signature(solana_account: SOLAccount) -> None:
    """
    Tests that the verification function raises BadSignatureError when provided
    with a valid public key but a randomly forged 64-byte signature.
    """
    # 1. Arrange: Create and sign a valid message
    message: Dict[str, Any] = asdict(
        Message(
            "SOL",
            solana_account.get_address(),
            "POST",
            "SomeHash",
        )
    )
    await solana_account.sign_message(message)
    assert "signature" in message
    
    # 2. Act: Create a forged signature
    # Solana signatures are 64 bytes. Create a base58 string from 64 null bytes.
    forged: str = base58.b58encode(bytes(64)).decode("utf-8")

    # 3. Assert: Verification must fail
    with pytest.raises(BadSignatureError):
        verify_signature(forged, message["sender"], get_verification_buffer(message))


@pytest.mark.asyncio
async def test_sign_raw(solana_account: SOLAccount) -> None:
    """
    Tests the sign_raw utility for signing an arbitrary byte buffer.
    """
    # 1. Arrange: Arbitrary buffer
    buffer = b"SomeBufferToSign"
    
    # 2. Act: Sign the raw buffer
    signature: bytes = await solana_account.sign_raw(buffer)
    assert isinstance(signature, bytes)
    
    # 3. Assert: Verify the raw signature using the account's address (public key)
    verify_signature(signature, solana_account.get_address(), buffer)


def test_parse_solana_private_key_bytes() -> None:
    """
    Tests parsing a 32-byte raw private key (seed).
    """
    # Valid 32-byte private key
    private_key_bytes = bytes(range(32))
    parsed_key: bytes = parse_private_key(private_key_bytes)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32
    assert parsed_key == private_key_bytes

    # Invalid private key (too short)
    with pytest.raises(
        ValueError, match="The private key in bytes must be exactly 32 bytes long."
    ):
        parse_private_key(bytes(range(31)))


def test_parse_solana_private_key_base58() -> None:
    """
    Tests parsing a private key encoded in Base58 (either 32-byte seed or 64-byte keypair).
    """
    # Valid 32-byte seed encoded in Base58
    seed_bytes = bytes(range(32))
    base58_key: str = base58.b58encode(seed_bytes).decode("utf-8")
    parsed_key: bytes = parse_private_key(base58_key)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32
    assert parsed_key == seed_bytes

    # Invalid base58 key (not decodable)
    with pytest.raises(ValueError, match="Invalid base58 encoded private key"):
        parse_private_key("invalid_base58_key")

    # Invalid base58 key (wrong length after decoding)
    with pytest.raises(
        ValueError,
        match="The base58 decoded private key must be either 32 or 64 bytes long.",
    ):
        # 31 bytes -> invalid length
        parse_private_key(base58.b58encode(bytes(range(31))).decode("utf-8"))


def test_parse_solana_private_key_list() -> None:
    """
    Tests parsing a private key supplied as a list of integers (Solana's JSON keypair format).
    The function should extract only the first 32 bytes (the private key/seed).
    """
    # Valid list of uint8 integers (64 elements: 32 bytes private key + 32 bytes public key)
    uint8_list: List[int] = list(range(64))
    parsed_key: bytes = parse_private_key(uint8_list)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32
    # Ensure only the first 32 elements are taken
    assert parsed_key == bytes(range(32))

    # Invalid list (contains non-integers)
    with pytest.raises(ValueError, match="Invalid uint8 array"):
        parse_private_key([1, 2, "not an int", 4])  # type: ignore 

    # Invalid list (less than 32 elements)
    with pytest.raises(
        ValueError, match="The uint8 array must contain at least 32 elements."
    ):
        parse_private_key(list(range(31)))
