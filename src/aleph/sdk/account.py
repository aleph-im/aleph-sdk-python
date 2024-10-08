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
from aleph.sdk.types import AccountFromPrivateKey

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=AccountFromPrivateKey)


def load_chain_account_type(chain: Chain) -> Type[AccountFromPrivateKey]:
    chain_account_map: Dict[Chain, Type[AccountFromPrivateKey]] = {
        Chain.ETH: ETHAccount,
        Chain.AVAX: ETHAccount,
        Chain.SOL: SOLAccount,
        Chain.BASE: ETHAccount,
    }
    return chain_account_map.get(chain) or ETHAccount


def account_from_hex_string(private_key_str: str, account_type: Type[T]) -> T:
    if private_key_str.startswith("0x"):
        private_key_str = private_key_str[2:]
    return account_type(bytes.fromhex(private_key_str))


def account_from_file(private_key_path: Path, account_type: Type[T]) -> T:
    private_key = private_key_path.read_bytes()
    return account_type(private_key)


def _load_account(
    private_key_str: Optional[str] = None,
    private_key_path: Optional[Path] = None,
    account_type: Optional[Type[AccountFromPrivateKey]] = None,
) -> AccountFromPrivateKey:
    """Load private key from a string or a file. takes the string argument in priority"""
    if private_key_str or (private_key_path and private_key_path.is_file()):
        if account_type:
            if private_key_path and private_key_path.is_file():
                return account_from_file(private_key_path, account_type)
            elif private_key_str:
                return account_from_hex_string(private_key_str, account_type)
            else:
                raise ValueError("Any private key specified")
        else:
            main_configuration = load_main_configuration(settings.CONFIG_FILE)
            if main_configuration:
                account_type = load_chain_account_type(main_configuration.chain)
                logger.debug(
                    f"Detected {main_configuration.chain} account for path {settings.CONFIG_FILE}"
                )
            else:
                account_type = ETHAccount  # Defaults to ETHAccount
                logger.warning(
                    f"No main configuration data found in {settings.CONFIG_FILE}, defaulting to {account_type.__name__}"
                )
            if private_key_path and private_key_path.is_file():
                return account_from_file(private_key_path, account_type)
            elif private_key_str:
                return account_from_hex_string(private_key_str, account_type)
            else:
                raise ValueError("Any private key specified")

    elif settings.REMOTE_CRYPTO_HOST:
        logger.debug("Using remote account")
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            RemoteAccount.from_crypto_host(
                host=settings.REMOTE_CRYPTO_HOST,
                unix_socket=settings.REMOTE_CRYPTO_UNIX_SOCKET,
            )
        )
    else:
        account_type = ETHAccount  # Defaults to ETHAccount
        new_private_key = get_fallback_private_key()
        account = account_type(private_key=new_private_key)
        logger.info(
            f"Generated fallback private key with address {account.get_address()}"
        )
        return account
