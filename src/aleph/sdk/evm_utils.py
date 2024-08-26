from decimal import Decimal
from typing import List, Optional, Union

from aleph_message.models import Chain
from eth_utils import to_wei
from web3 import Web3
from web3.types import ChecksumAddress

from .conf import settings

MIN_ETH_BALANCE: float = 0.005
MIN_ETH_BALANCE_WEI = Decimal(to_wei(MIN_ETH_BALANCE, "ether"))
BALANCEOF_ABI = """[{
    "name": "balanceOf",
    "inputs": [{"name": "account", "type": "address"}],
    "outputs": [{"name": "balance", "type": "uint256"}],
    "constant": true,
    "payable": false,
    "stateMutability": "view",
    "type": "function"
}]"""


def to_human_readable_token(amount: Decimal) -> float:
    return float(amount / (Decimal(10) ** Decimal(settings.TOKEN_DECIMALS)))


def to_wei_token(amount: Decimal) -> Decimal:
    return amount * Decimal(10) ** Decimal(settings.TOKEN_DECIMALS)


def get_chain_id(chain: Union[Chain, str, None]) -> Optional[int]:
    """Returns the CHAIN_ID of a given EVM blockchain"""
    if chain:
        if chain in settings.CHAINS and settings.CHAINS[chain].chain_id:
            return settings.CHAINS[chain].chain_id
        else:
            raise ValueError(f"Unknown RPC for chain {chain}")
    return None


def get_rpc(chain: Union[Chain, str, None]) -> Optional[str]:
    """Returns the RPC to use for a given EVM blockchain"""
    if chain:
        if chain in settings.CHAINS and settings.CHAINS[chain].rpc:
            return settings.CHAINS[chain].rpc
        else:
            raise ValueError(f"Unknown RPC for chain {chain}")
    return None


def get_token_address(chain: Union[Chain, str, None]) -> Optional[ChecksumAddress]:
    if chain:
        if chain in settings.CHAINS:
            address = settings.CHAINS[chain].super_token
            if address:
                try:
                    return Web3.to_checksum_address(address)
                except ValueError:
                    raise ValueError(f"Invalid token address {address}")
        else:
            raise ValueError(f"Unknown token for chain {chain}")
    return None


def get_super_token_address(
    chain: Union[Chain, str, None]
) -> Optional[ChecksumAddress]:
    if chain:
        if chain in settings.CHAINS:
            address = settings.CHAINS[chain].super_token
            if address:
                try:
                    return Web3.to_checksum_address(address)
                except ValueError:
                    raise ValueError(f"Invalid token address {address}")
        else:
            raise ValueError(f"Unknown super_token for chain {chain}")
    return None


def get_chains_with_holding() -> List[Union[Chain, str]]:
    return [chain for chain, info in settings.CHAINS.items() if info.active]


def get_chains_with_super_token() -> List[Union[Chain, str]]:
    return [
        chain
        for chain, info in settings.CHAINS.items()
        if info.active and info.super_token
    ]
