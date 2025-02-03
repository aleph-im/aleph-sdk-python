from decimal import Decimal
from pathlib import Path
from typing import Awaitable, Optional

from aleph_message.models import Chain
from eth_account import Account  # type: ignore

from ..evm_utils import FlowUpdate
from .common import get_fallback_private_key
from .ethereum import ETHAccount


class EVMAccount(ETHAccount):
    def __init__(self, private_key: bytes, chain: Optional[Chain] = None):
        super().__init__(private_key, chain)
        # Decide if we have to send also the specified chain value or always use ETH
        # if chain:
        #     self.CHAIN = chain

    @staticmethod
    def from_mnemonic(mnemonic: str, chain: Optional[Chain] = None) -> "EVMAccount":
        Account.enable_unaudited_hdwallet_features()
        return EVMAccount(
            private_key=Account.from_mnemonic(mnemonic=mnemonic).key, chain=chain
        )

    def get_token_balance(self) -> Decimal:
        raise ValueError(f"Token not implemented for this chain {self.CHAIN}")

    def get_super_token_balance(self) -> Decimal:
        raise ValueError(f"Super token not implemented for this chain {self.CHAIN}")

    def can_start_flow(self, flow: Decimal) -> bool:
        raise ValueError(f"Flow checking not implemented for this chain {self.CHAIN}")

    def create_flow(self, receiver: str, flow: Decimal) -> Awaitable[str]:
        raise ValueError(f"Flow creation not implemented for this chain {self.CHAIN}")

    def get_flow(self, receiver: str):
        raise ValueError(f"Get flow not implemented for this chain {self.CHAIN}")

    def update_flow(self, receiver: str, flow: Decimal) -> Awaitable[str]:
        raise ValueError(f"Flow update not implemented for this chain {self.CHAIN}")

    def delete_flow(self, receiver: str) -> Awaitable[str]:
        raise ValueError(f"Flow deletion not implemented for this chain {self.CHAIN}")

    def manage_flow(
        self, receiver: str, flow: Decimal, update_type: FlowUpdate
    ) -> Awaitable[Optional[str]]:
        raise ValueError(f"Flow management not implemented for this chain {self.CHAIN}")


def get_fallback_account(
    path: Optional[Path] = None, chain: Optional[Chain] = None
) -> ETHAccount:
    return ETHAccount(private_key=get_fallback_private_key(path=path), chain=chain)
