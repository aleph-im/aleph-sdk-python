import asyncio
import logging
from pathlib import Path
from typing import Dict, Optional, Type, TypeVar

from aleph_message.models import Chain

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.chains.remote import RemoteAccount
from aleph.sdk.chains.solana import SOLAccount
from aleph.sdk.conf import load_main_configuration, settings
from aleph.sdk.evm_utils import get_chains_with_super_token
from aleph.sdk.types import AccountFromPrivateKey

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=AccountFromPrivateKey)

chain_account_map: Dict[Chain, Type[T]] = {  # type: ignore
    Chain.ETH: ETHAccount,
    Chain.AVAX: ETHAccount,
    Chain.BASE: ETHAccount,
    Chain.SOL: SOLAccount,
}


def load_chain_account_type(chain: Chain) -> Type[AccountFromPrivateKey]:
    return chain_account_map.get(chain) or ETHAccount  # type: ignore


def account_from_hex_string(
    private_key_str: str,
    account_type: Optional[Type[T]],
    chain: Optional[Chain] = None,
) -> AccountFromPrivateKey:
    if private_key_str.startswith("0x"):
        private_key_str = private_key_str[2:]

    if not chain:
        if not account_type:
            account_type = load_chain_account_type(Chain.ETH)  # type: ignore
        return account_type(bytes.fromhex(private_key_str))  # type: ignore

    account_type = load_chain_account_type(chain)
    account = account_type(bytes.fromhex(private_key_str))
    if chain in get_chains_with_super_token():
        account.switch_chain(chain)
    return account  # type: ignore


def account_from_file(
    private_key_path: Path,
    account_type: Optional[Type[T]],
    chain: Optional[Chain] = None,
) -> AccountFromPrivateKey:
    private_key = private_key_path.read_bytes()

    if not chain:
        if not account_type:
            account_type = load_chain_account_type(Chain.ETH)  # type: ignore
        return account_type(private_key)  # type: ignore

    account_type = load_chain_account_type(chain)
    account = account_type(private_key)
    if chain in get_chains_with_super_token():
        account.switch_chain(chain)
    return account


def _load_account(
    private_key_str: Optional[str] = None,
    private_key_path: Optional[Path] = None,
    account_type: Optional[Type[AccountFromPrivateKey]] = None,
    chain: Optional[Chain] = None,
) -> AccountFromPrivateKey:
    """Load an account from a private key string or file, or from the configuration file."""

    # Loads configuration if no account_type is specified
    if not account_type:
        config = load_main_configuration(settings.CONFIG_FILE)
        if config and hasattr(config, "chain"):
            account_type = load_chain_account_type(config.chain)
            logger.debug(
                f"Detected {config.chain} account for path {settings.CONFIG_FILE}"
            )
        else:
            account_type = account_type = load_chain_account_type(
                Chain.ETH
            )  # Defaults to ETHAccount
            logger.warning(
                f"No main configuration data found in {settings.CONFIG_FILE}, defaulting to {account_type and account_type.__name__}"
            )

    # Loads private key from a string
    if private_key_str:
        return account_from_hex_string(private_key_str, account_type, chain)
    # Loads private key from a file
    elif private_key_path and private_key_path.is_file():
        return account_from_file(private_key_path, account_type, chain)
    # For ledger keys
    elif settings.REMOTE_CRYPTO_HOST:
        logger.debug("Using remote account")
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            RemoteAccount.from_crypto_host(
                host=settings.REMOTE_CRYPTO_HOST,
                unix_socket=settings.REMOTE_CRYPTO_UNIX_SOCKET,
            )
        )
    # Fallback: config.path if set, else generate a new private key
    else:
        new_private_key = get_fallback_private_key()
        account = account_from_hex_string(
            bytes.hex(new_private_key), account_type, chain
        )
        logger.info(
            f"Generated fallback private key with address {account.get_address()}"
        )
        return account
