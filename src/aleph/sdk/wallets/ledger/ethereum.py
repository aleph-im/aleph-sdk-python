from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional

from aleph_message.models import Chain
from eth_typing import HexStr
from ledgerblue.Dongle import Dongle
from ledgereth import find_account, get_account_by_path, get_accounts
from ledgereth.comms import init_dongle
from ledgereth.messages import sign_message
from ledgereth.objects import LedgerAccount, SignedMessage
from ledgereth.transactions import sign_transaction
from web3.types import TxReceipt

from ...chains.common import get_verification_buffer
from ...chains.ethereum import BaseEthAccount
from ...utils import bytes_from_hex

logger = logging.getLogger(__name__)


class LedgerETHAccount(BaseEthAccount):
    """Account using the Ethereum app on Ledger hardware wallets."""

    _account: LedgerAccount
    _device: Dongle

    def __init__(
        self, account: LedgerAccount, device: Dongle, chain: Optional[Chain] = None
    ):
        """Initialize an aleph.im account instance that relies on a LedgerHQ
        device and the Ethereum Ledger application for signatures.

        See the static methods `self.from_address(...)` and `self.from_path(...)`
        for an easier method of instantiation.
        """
        super().__init__(chain=None)

        self._account = account
        self._device = device
        if chain:
            self.connect_chain(chain=chain)

    @staticmethod
    def get_accounts(
        device: Optional[Dongle] = None, count: int = 5
    ) -> List[LedgerAccount]:
        """Initialize an aleph.im account from a LedgerHQ device from
        a known wallet address.
        """
        device = device or init_dongle()
        accounts: List[LedgerAccount] = get_accounts(dongle=device, count=count)
        return accounts

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
        logger.warning(
            "Please Sign messages using ledger"
        )  # allow to propagate it to cli
        sig: SignedMessage = sign_message(
            msghash, dongle=self._device, sender_path=self._account.path
        )

        signature: HexStr = sig.signature

        message["signature"] = signature
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        """Sign a raw buffer."""
        logger.warning(
            "Please Sign messages using ledger"
        )  # allow to propagate it to cli
        sig: SignedMessage = sign_message(
            buffer, dongle=self._device, sender_path=self._account.path
        )
        signature: HexStr = sig.signature
        return bytes_from_hex(signature)

    async def _sign_and_send_transaction(self, tx_params: dict) -> str:
        """
        Sign and broadcast a transaction using the Ledger hardware wallet.
        Equivalent of the software _sign_and_send_transaction().

        @param tx_params: dict - Transaction parameters
        @returns: str - Transaction hash
        """
        if self._provider is None:
            raise ValueError("Provider not connected")

        def sign_and_send() -> TxReceipt:
            logger.warning(
                "Please Sign messages using ledger"
            )  # allow to propagate it to cli
            signed_tx = sign_transaction(
                tx=tx_params,
                sender_path=self._account.path,
                dongle=self._device,
            )

            provider = self._provider
            if provider is None:
                raise ValueError("Provider not connected")

            tx_hash = provider.eth.send_raw_transaction(bytes_from_hex(signed_tx))

            tx_receipt = provider.eth.wait_for_transaction_receipt(
                tx_hash,
                timeout=getattr(self, "TX_TIMEOUT", 120),  # optional custom timeout
            )

            return tx_receipt

        loop = asyncio.get_running_loop()
        tx_receipt = await loop.run_in_executor(None, sign_and_send)

        return tx_receipt["transactionHash"].hex()

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
