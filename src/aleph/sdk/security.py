from typing import Any
from importlib import import_module

from aleph_message.models import AlephMessage

from aleph.sdk.chains.common import get_verification_buffer

validator_chains_map = {
    # TODO: Add AVAX
    "ETH": "ethereum",
    "SOL": "sol",
    "CSDK": "cosmos",
    "DOT": "substrate",
    "NULS2": "nuls2",
    "TEZOS": "tezos",
}


def try_import_verify_signature(chain: str) -> Any:
    """Try to import a chain signature validator."""
    try:
        return import_module(f"aleph.sdk.chains.{chain}").verify_signature
    except (ImportError, AttributeError):
        return None


validators = {
    key: try_import_verify_signature(value)
    for key, value in validator_chains_map.items()
}


def verify_signature(message: AlephMessage) -> None:
    """Verify the signature of a message."""
    if message.chain not in validators:
        raise ValueError(f"Chain {message.chain} is not supported.")
    validator = validators[message.chain]
    if validator is None:
        raise ValueError(f"Chain {message.chain} is not installed. Install it with `aleph-sdk-python[{message.chain}]`.")
    signature = message.signature
    public_key = message.sender
    message = get_verification_buffer(message.dict())
    validator(signature, public_key, message)
