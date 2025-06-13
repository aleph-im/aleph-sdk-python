from typing import TYPE_CHECKING, List, Optional

import aiohttp
from aleph_message.models import ItemHash

from aleph.sdk.conf import settings
from aleph.sdk.types import Dns, DnsListAdapter
from aleph.sdk.utils import sanitize_url

if TYPE_CHECKING:
    from aleph.sdk.client.http import AlephHttpClient


class DNSService:
    """
    This Service mostly made to get active dns for instance:
        `https://api.dns.public.aleph.sh/instances/list`
    """

    def __init__(self, client: "AlephHttpClient"):
        self._client = client

    async def get_public_dns(self) -> List[Dns]:
        """
        Get all the public dns ha
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(sanitize_url(settings.DNS_API)) as resp:
                resp.raise_for_status()
                raw = await resp.json()

        return DnsListAdapter.validate_json(raw)

    async def get_dns_for_instance(self, vm_hash: ItemHash) -> Optional[Dns]:
        dns_list: List[Dns] = await self.get_public_dns()
        for dns in dns_list:
            if dns.item_hash == vm_hash:
                return dns
        return None
