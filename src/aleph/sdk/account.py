import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type, TypeVar, Union, overload

import base58
from aleph_message.models import Chain

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.chains.remote import RemoteAccount
from aleph.sdk.chains.solana import SOLAccount
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey
from aleph.sdk.utils import parse_solana_private_key, solana_private_key_from_bytes

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=AccountFromPrivateKey)

CHAIN_TO_ACCOUNT_MAP: Dict[Chain, Type[AccountFromPrivateKey]] = {
    Chain.ETH: ETHAccount,
    Chain.AVAX: ETHAccount,
    Chain.SOL: SOLAccount,
    Chain.BASE: ETHAccount,
}


def detect_chain_from_private_key(private_key: Union[str, List[int], bytes]) -> Chain:
    """
    Detect the blockchain chain based on the private key format.
    - Chain.ETH for Ethereum (EVM) private keys
    - Chain.SOL for Solana private keys (base58 or uint8 format).

    Raises:
        ValueError: If the private key format is invalid or not recognized.
    """
    if isinstance(private_key, (str, bytes)) and is_valid_private_key(
        private_key, ETHAccount
    ):
        return Chain.ETH

    elif is_valid_private_key(private_key, SOLAccount):
        return Chain.SOL

    else:
        raise ValueError("Unsupported private key format. Unable to detect chain.")


@overload
def is_valid_private_key(
    private_key: Union[str, bytes], account_type: Type[ETHAccount]
) -> bool: ...


@overload
def is_valid_private_key(
    private_key: Union[str, List[int], bytes], account_type: Type[SOLAccount]
) -> bool: ...


def is_valid_private_key(
    private_key: Union[str, List[int], bytes], account_type: Type[T]
) -> bool:
    """
    Check if the private key is valid for either Ethereum or Solana based on the account type.
    """
    try:
        if account_type == ETHAccount:
            # Handle Ethereum private key validation
            if isinstance(private_key, str):
                if private_key.startswith("0x"):
                    private_key = private_key[2:]
                private_key = bytes.fromhex(private_key)
            elif isinstance(private_key, list):
                raise ValueError("Ethereum keys cannot be a list of integers")

            account_type(private_key)

        elif account_type == SOLAccount:
            # Handle Solana private key validation
            if isinstance(private_key, bytes):
                return len(private_key) == 64
            elif isinstance(private_key, str):
                decoded_key = base58.b58decode(private_key)
                return len(decoded_key) == 64
            elif isinstance(private_key, list):
                return len(private_key) == 64 and all(
                    isinstance(i, int) and 0 <= i <= 255 for i in private_key
                )

        return True
    except Exception:
        return False


def account_from_hex_string(private_key_str: str, account_type: Type[T]) -> T:
    if private_key_str.startswith("0x"):
        private_key_str = private_key_str[2:]
    return account_type(bytes.fromhex(private_key_str))


def account_from_file(private_key_path: Path, account_type: Type[T]) -> T:
    private_key = private_key_path.read_bytes()
    if account_type == SOLAccount:
        private_key = parse_solana_private_key(
            solana_private_key_from_bytes(private_key)
        )

    return account_type(private_key)


def _load_account(
    private_key_str: Optional[str] = None,
    private_key_path: Optional[Path] = None,
    account_type: Type[AccountFromPrivateKey] = ETHAccount,
) -> AccountFromPrivateKey:
    """Load private key from a string or a file. takes the string argument in priority"""

    if private_key_str:
        # Check Account type based on private-key string format (base58 / uint for solana)
        private_key_chain = detect_chain_from_private_key(private_key=private_key_str)
        if private_key_chain == Chain.SOL:
            account_type = SOLAccount
            logger.debug("Solana private key is detected")
            parsed_key = parse_solana_private_key(private_key_str)
            return account_type(parsed_key)
        logger.debug("Using account from string")
        return account_from_hex_string(private_key_str, account_type)
    elif private_key_path and private_key_path.is_file():
        if private_key_path:
            try:
                # Look for the account by private_key_path in CONFIG_FILE
                with open(settings.CONFIG_FILE, "r") as file:
                    accounts = json.load(file)

                matching_account = next(
                    (
                        account
                        for account in accounts
                        if account["path"] == str(private_key_path)
                    ),
                    None,
                )

                if matching_account:
                    chain = Chain(matching_account["chain"])
                    account_type = CHAIN_TO_ACCOUNT_MAP.get(chain, ETHAccount)
                    if account_type is None:
                        account_type = ETHAccount
                    logger.debug(
                        f"Detected {chain} account for path {private_key_path}"
                    )
                else:
                    logger.warning(
                        f"No matching account found for path {private_key_path}, defaulting to {account_type.__name__}"
                    )

            except FileNotFoundError:
                logger.warning(
                    f"CONFIG_FILE not found, using default account type {account_type.__name__}"
                )
            except json.JSONDecodeError:
                logger.error(
                    f"Invalid format in CONFIG_FILE, unable to load account info."
                )
                raise ValueError(f"Invalid format in {settings.CONFIG_FILE}.")
            except Exception as e:
                logger.error(f"Error loading accounts from config: {e}")
                raise ValueError(
                    f"Could not find matching account for path {private_key_path}."
                )

        return account_from_file(private_key_path, account_type)
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
        new_private_key = get_fallback_private_key()
        account = account_type(private_key=new_private_key)
        logger.info(
            f"Generated fallback private key with address {account.get_address()}"
        )
        return account
