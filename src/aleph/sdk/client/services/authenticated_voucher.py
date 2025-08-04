from typing import TYPE_CHECKING, Optional, overload

from typing_extensions import override

from aleph.sdk.types import Voucher

from .voucher import Vouchers

if TYPE_CHECKING:
    from aleph.sdk.client.abstract import AuthenticatedAlephClient


class AuthenticatedVoucher(Vouchers):
    """
    This service is same logic than Vouchers but allow to don't pass address
    to use account address
    """

    def __init__(self, client: "AuthenticatedAlephClient"):
        super().__init__(client)

    @overload
    def _resolve_address(self, address: str) -> str: ...

    @overload
    def _resolve_address(self, address: None) -> str: ...

    @override
    def _resolve_address(self, address: Optional[str] = None) -> str:
        """
        Resolve the address to use. Prefer the provided address, fallback to account.
        """
        if address:
            return address
        if self._client.account:
            return self._client.account.get_address()

        raise ValueError("No address provided and no account configured")

    @override
    async def get_vouchers(self, address: Optional[str] = None) -> list[Voucher]:
        """
        Retrieve all vouchers for the account / specific address, across EVM and Solana chains.
        """
        address = address or self._client.account.get_address()
        return await super().get_vouchers(address=address)

    @override
    async def get_evm_vouchers(self, address: Optional[str] = None) -> list[Voucher]:
        """
        Retrieve vouchers specific to EVM chains for a specific address.
        """
        address = address or self._client.account.get_address()
        return await super().get_evm_vouchers(address=address)

    @override
    async def get_solana_vouchers(self, address: Optional[str] = None) -> list[Voucher]:
        """
        Fetch Solana vouchers for a specific address.
        """
        address = address or self._client.account.get_address()
        return await super().get_solana_vouchers(address=address)
