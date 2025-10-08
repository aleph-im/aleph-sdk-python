from typing import TYPE_CHECKING, Optional

from aleph_message.models import ItemHash

from aleph.sdk.client.services.base import AggregateConfig, BaseService
from aleph.sdk.types import AllForwarders, Ports

if TYPE_CHECKING:
    pass


class PortForwarder(BaseService[AllForwarders]):
    """
    Ports Forwarder Logic
    """

    aggregate_key = "port-forwarding"
    model_cls = AllForwarders

    def __init__(self, client):
        super().__init__(client=client)

    async def get_address_ports(self, address: str) -> AggregateConfig[AllForwarders]:
        result = await self.get_config(address=address)
        return result

    async def get_ports(self, item_hash: ItemHash, address: str) -> Optional[Ports]:
        """
        Get Ports Forwarder of Instance / Program / IPFS  website from aggregate
        """
        ports_config: AggregateConfig[AllForwarders] = await self.get_address_ports(
            address=address
        )

        if ports_config.data is None:
            return Ports(ports={})

        for forwarder in ports_config.data:
            ports_map = forwarder.root

            if str(item_hash) in ports_map:
                return ports_map[str(item_hash)]

        return Ports(ports={})
