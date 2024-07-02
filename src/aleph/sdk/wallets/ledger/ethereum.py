from __future__ import annotations

from typing import Dict, List, Optional

from eth_typing import HexStr
from ledgerblue.Dongle import Dongle
from ledgereth import find_account, get_account_by_path, get_accounts
from ledgereth.comms import init_dongle
from ledgereth.messages import sign_message
from ledgereth.objects import LedgerAccount, SignedMessage

from ...chains.common import BaseAccount, get_verification_buffer
from ...utils import bytes_from_hex


class LedgerETHAccount(BaseAccount):
    """Account using the Ethereum app on Ledger hardware wallets."""

    CHAIN = "ETH"
    CURVE = "secp256k1"
    _account: LedgerAccount
    _device: Dongle

    def __init__(self, account: LedgerAccount, device: Dongle):
        """Initialize an aleph.im account instance that relies on a LedgerHQ
        device and the Ethereum Ledger application for signatures.

        See the static methods `self.from_address(...)` and `self.from_path(...)`
        for an easier method of instantiation.
        """
        self._account = account
        self._device = device

    @staticmethod
    def from_address(
        address: str, device: Optional[Dongle] = None
    ) -> Optional[LedgerETHAccount]:
        """Initialize an aleph.im account from a LedgerHQ device from
        a known wallet address.
        """
        device = device or init_dongle()
        account: Optional[LedgerAccount] = find_account(
            address=address, dongle=device, count=5
        )
        return (
            LedgerETHAccount(
                account=account,
                device=device,
            )
            if account
            else None
        )

    @staticmethod
    def from_path(path: str, device: Optional[Dongle] = None) -> LedgerETHAccount:
        """Initialize an aleph.im account from a LedgerHQ device from
        a known wallet account path."""
        device = device or init_dongle()
        account: LedgerAccount = get_account_by_path(path_string=path, dongle=device)
        return LedgerETHAccount(
            account=account,
            device=device,
        )

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        message: Dict = self._setup_sender(message)

        # TODO: Check why the code without a wallet uses `encode_defunct`.
        msghash: bytes = get_verification_buffer(message)
        sig: SignedMessage = sign_message(msghash, dongle=self._device)

        signature: HexStr = sig.signature

        message["signature"] = signature
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        """Sign a raw buffer."""
        sig: SignedMessage = sign_message(buffer, dongle=self._device)
        signature: HexStr = sig.signature
        return bytes_from_hex(signature)

    def get_address(self) -> str:
        return self._account.address

    def get_public_key(self) -> str:
        """Obtaining the public key is not supported by the ledgereth library
        we use, and may not be supported by LedgerHQ devices at all.
        """
        raise NotImplementedError()


def get_fallback_account() -> LedgerETHAccount:
    """Returns the first account available on the device first device found."""
    device: Dongle = init_dongle()
    accounts: List[LedgerAccount] = get_accounts(dongle=device, count=1)
    if not accounts:
        raise ValueError("No account found on device")
    account = accounts[0]
    return LedgerETHAccount(account=account, device=device)
