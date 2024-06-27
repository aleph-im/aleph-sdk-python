from importlib import import_module
from typing import Callable, Dict, Optional, Union

from aleph_message.models import AlephMessage, Chain

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.query.responses import Post


def _try_import_verify_signature(
    chain: str,
) -> Optional[
    Callable[[Union[bytes, str], Union[bytes, str], Union[bytes, str]], None]
]:
    """Try to import a chain signature validator."""
    try:
        return import_module(f"aleph.sdk.chains.{chain}").verify_signature
    except (ImportError, AttributeError):
        return None


# This is a dict containing all currently available signature validators,
# indexed by their Chain abbreviation.
#
# Ex.: validators["SOL"] -> aleph.sdk.chains.solana.verify_signature()
VALIDATORS: Dict[
    Chain,
    Optional[Callable[[Union[bytes, str], Union[bytes, str], Union[bytes, str]], None]],
] = {
    key: _try_import_verify_signature(value)
    for key, value in {
        # TODO: Add AVAX
        Chain.ETH: "ethereum",
        Chain.SOL: "sol",
        Chain.CSDK: "cosmos",
        Chain.DOT: "substrate",
        Chain.NULS2: "nuls2",
        Chain.TEZOS: "tezos",
    }.items()
}


def verify_message_signature(message: Union[AlephMessage, Post]) -> None:
    """Verify the signature of a message, raise an error if invalid or unsupported.
    A BadSignatureError is raised when the signature is incorrect.
    A ValueError is raised when the chain is not supported or required dependencies are  missing.
    """
    if message.chain not in VALIDATORS:
        raise ValueError(f"Chain {message.chain} is not supported.")

    validator = VALIDATORS[message.chain]
    if validator is None:
        raise ValueError(
            f"Chain {message.chain} is not installed. Install it with `aleph-sdk-python[{message.chain}]`."
        )

    signature = message.signature
    public_key = message.sender
    message = get_verification_buffer(message.dict())

    # to please mypy
    assert isinstance(signature, (str, bytes))

    validator(signature, public_key, message)
