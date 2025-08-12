from typing import TYPE_CHECKING, Optional, Tuple

from aleph_message.models import AggregateMessage, ItemHash
from aleph_message.status import MessageStatus

from aleph.sdk.client.services.base import AggregateConfig
from aleph.sdk.client.services.port_forwarder import PortForwarder
from aleph.sdk.exceptions import MessageNotProcessed, NotAuthorize
from aleph.sdk.types import AllForwarders, Ports
from aleph.sdk.utils import safe_getattr

if TYPE_CHECKING:
    from aleph.sdk.client.abstract import AuthenticatedAlephClient


class AuthenticatedPortForwarder(PortForwarder):
    """
    Authenticated Port Forwarder services with create and update capabilities
    """

    def __init__(self, client: "AuthenticatedAlephClient"):
        super().__init__(client)

    async def _verify_status_processed_and_ownership(
        self, item_hash: ItemHash
    ) -> Tuple[AggregateMessage, MessageStatus]:
        """
        Verify that the message is well processed (and not rejected / pending),
        This also verify the ownership of the message
        """
        message: AggregateMessage
        status: MessageStatus
        message, status = await self._client.get_message(
            item_hash=item_hash,
            with_status=True,
        )

        # We ensure message is not Rejected (Might not be processed yet)
        if status not in [MessageStatus.PROCESSED, MessageStatus.PENDING]:
            raise MessageNotProcessed(item_hash=item_hash, status=status)

        message_content = safe_getattr(message, "content")
        address = safe_getattr(message_content, "address")

        if (
            not hasattr(self._client, "account")
            or address != self._client.account.get_address()
        ):
            current_address = (
                self._client.account.get_address()
                if hasattr(self._client, "account")
                else "unknown"
            )
            raise NotAuthorize(
                item_hash=item_hash,
                target_address=address,
                current_address=current_address,
            )
        return message, status

    async def get_address_ports(
        self, address: Optional[str] = None
    ) -> AggregateConfig[AllForwarders]:
        """
        Get all port forwarding configurations for an address

        Args:
            address: The address to fetch configurations for.
                    If None, uses the authenticated client's account address.

        Returns:
            Port forwarding configurations
        """
        if address is None:
            if not hasattr(self._client, "account") or not self._client.account:
                raise ValueError("No account provided and client is not authenticated")
            address = self._client.account.get_address()

        return await super().get_address_ports(address=address)

    async def get_ports(
        self, item_hash: ItemHash = None, address: Optional[str] = None
    ) -> Optional[Ports]:
        """
        Get port forwarding configuration for a specific item hash

        Args:
            address: The address to fetch configurations for.
                    If None, uses the authenticated client's account address.
            item_hash: The hash of the item to get configuration for

        Returns:
            Port configuration if found, otherwise empty Ports object
        """
        if address is None:
            if not hasattr(self._client, "account") or not self._client.account:
                raise ValueError("No account provided and client is not authenticated")
            address = self._client.account.get_address()

        if item_hash is None:
            raise ValueError("item_hash must be provided")

        return await super().get_ports(address=address, item_hash=item_hash)

    async def create_ports(
        self, item_hash: ItemHash, ports: Ports
    ) -> Tuple[AggregateMessage, MessageStatus]:
        """
        Create a new port forwarding configuration for an item hash

        Args:
            item_hash: The hash of the item (instance/program/IPFS website)
            ports: Dictionary mapping port numbers to PortFlags

        Returns:
            Dictionary with the result of the operation
        """
        if not hasattr(self._client, "account") or not self._client.account:
            raise ValueError("An account is required for this operation")

        # Pre Check
        # _, _ = await self._verify_status_processed_and_ownership(item_hash=item_hash)

        content = {str(item_hash): ports.model_dump()}

        # Check if create_aggregate exists on the client
        return await self._client.create_aggregate(  # type: ignore
            key=self.aggregate_key, content=content
        )

    async def update_ports(
        self, item_hash: ItemHash, ports: Ports
    ) -> Tuple[AggregateMessage, MessageStatus]:
        """
        Update an existing port forwarding configuration for an item hash

        Args:
            item_hash: The hash of the item (instance/program/IPFS website)
            ports: Dictionary mapping port numbers to PortFlags

        Returns:
            Dictionary with the result of the operation
        """
        if not hasattr(self._client, "account") or not self._client.account:
            raise ValueError("An account is required for this operation")

        # Pre Check
        # _, _ = await self._verify_status_processed_and_ownership(item_hash=item_hash)

        content = {}

        content[str(item_hash)] = ports.model_dump()

        message, status = await self._client.create_aggregate(  # type: ignore
            key=self.aggregate_key, content=content
        )

        return message, status

    async def delete_ports(
        self, item_hash: ItemHash
    ) -> Tuple[AggregateMessage, MessageStatus]:
        """
        Delete port forwarding configuration for an item hash

        Args:
            item_hash: The hash of the item (instance/program/IPFS website) to delete configuration for

        Returns:
            Dictionary with the result of the operation
        """
        if not hasattr(self._client, "account") or not self._client.account:
            raise ValueError("An account is required for this operation")

        # Pre Check
        # _, _ = await self._verify_status_processed_and_ownership(item_hash=item_hash)

        # Get the Port Config of the item_hash
        port: Optional[Ports] = await self.get_ports(item_hash=item_hash)
        if not port:
            raise

        content = {}
        content[str(item_hash)] = port.model_dump()

        # Create a new aggregate with the updated content
        message, status = await self._client.create_aggregate(  # type: ignore
            key=self.aggregate_key, content=content
        )
        return message, status
