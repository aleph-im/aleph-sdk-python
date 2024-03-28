from importlib import import_module
from typing import Any, Union

from aleph_message.models import AlephMessage, Chain

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.query.responses import Post

validator_chains_map = {
    # TODO: Add AVAX
    Chain.ETH: "ethereum",
    Chain.SOL: "sol",
    Chain.CSDK: "cosmos",
    Chain.DOT: "substrate",
    Chain.NULS2: "nuls2",
    Chain.TEZOS: "tezos",
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


def verify_message_signature(message: Union[AlephMessage, Post]) -> None:
    """Verify the signature of a message, raise an error if invalid or unsupported.
    A BadSignatureError is raised when the signature is incorrect.
    A ValueError is raised when the chain is not supported or required dependencies are  missing.
    """
    if message.chain not in validators:
        raise ValueError(f"Chain {message.chain} is not supported.")
    validator = validators[message.chain]
    if validator is None:
        raise ValueError(
            f"Chain {message.chain} is not installed. Install it with `aleph-sdk-python[{message.chain}]`."
        )
    signature = message.signature
    public_key = message.sender
    message = get_verification_buffer(message.dict())
    validator(signature, public_key, message)
