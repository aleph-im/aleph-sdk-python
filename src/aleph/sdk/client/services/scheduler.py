from typing import TYPE_CHECKING, Optional

import aiohttp
from aiohttp import ClientResponseError
from aleph_message.models import ItemHash

from aleph.sdk.conf import settings
from aleph.sdk.types import AllocationItem, SchedulerNodes, SchedulerPlan
from aleph.sdk.utils import sanitize_url

if TYPE_CHECKING:
    from aleph.sdk.client.http import AlephHttpClient


class Scheduler:
    """
    This Service is made to interact with scheduler API:
        `https://scheduler.api.aleph.cloud/`
    """

    def __init__(self, client: "AlephHttpClient"):
        self._client = client

    async def get_plan(self) -> SchedulerPlan:
        url = f"{sanitize_url(settings.SCHEDULER_URL)}/api/v0/plan"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                raw = await resp.json()
                return SchedulerPlan.model_validate(raw)

    async def get_nodes(self) -> SchedulerNodes:
        url = f"{sanitize_url(settings.SCHEDULER_URL)}/api/v0/nodes"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                raw = await resp.json()

                return SchedulerNodes.model_validate(raw)

    async def get_allocation(self, vm_hash: ItemHash) -> Optional[AllocationItem]:
        """
        Fetch allocation information for a given VM hash.
        """
        url = f"{sanitize_url(settings.SCHEDULER_URL)}/api/v0/allocation/{vm_hash}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    payload = await resp.json()
            return AllocationItem.model_validate(payload)
        except ClientResponseError as e:
            if e.status == 404:  # Allocation can't be find on scheduler
                return None
            raise e
