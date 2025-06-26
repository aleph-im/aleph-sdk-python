from typing import TYPE_CHECKING, Dict, Optional, Union

import aiohttp
from aiohttp.client_exceptions import ClientResponseError
from aleph_message.models import ItemHash

from aleph.sdk.conf import settings
from aleph.sdk.exceptions import MethodNotAvailableOnCRN, VmNotFoundOnHost
from aleph.sdk.types import CrnExecutionV1, CrnExecutionV2, CrnV1List, CrnV2List
from aleph.sdk.utils import sanitize_url

if TYPE_CHECKING:
    from aleph.sdk.client.http import AlephHttpClient


class Crn:
    """
    This services allow interact with CRNS API
    TODO: ADD
        /about/executions/details
        /about/executions/records
        /about/usage/system
        /about/certificates
        /about/capability
        /about/config
        /status/check/fastapi
        /status/check/fastapi/legacy
        /status/check/host
        /status/check/version
        /status/check/ipv6
        /status/config
    """

    def __init__(self, client: "AlephHttpClient"):
        self._client = client

    async def get_last_crn_version(self):
        """
        Fetch Last version tag from aleph-vm github repo
        """
        # Create a new session for external domain requests
        async with aiohttp.ClientSession() as session:
            async with session.get(settings.CRN_VERSION_URL) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return data.get("tag_name")

    async def get_crns_list(self, only_active: bool = True) -> dict:
        """
        Query a persistent VM running on aleph.im to retrieve list of CRNs:
        https://crns-list.aleph.sh/crns.json

        Parameters
        ----------
        only_active : bool
            If True (the default), only return active CRNs (i.e. `filter_inactive=false`).
            If False, return all CRNs (i.e. `filter_inactive=true`).

        Returns
        -------
        dict
            The parsed JSON response from /crns.json.
        """
        # We want filter_inactive = (not only_active)
        # Convert bool to string for the query parameter
        filter_inactive_str = str(not only_active).lower()
        params = {"filter_inactive": filter_inactive_str}

        # Create a new session for external domain requests
        async with aiohttp.ClientSession() as session:
            async with session.get(
                sanitize_url(settings.CRN_LIST_URL), params=params
            ) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def get_active_vms_v2(self, crn_address: str) -> CrnV2List:
        endpoint = "/v2/about/executions/list"

        full_url = sanitize_url(crn_address + endpoint)

        async with aiohttp.ClientSession() as session:
            async with session.get(full_url) as resp:
                resp.raise_for_status()
                raw = await resp.json()
                vm_mmap = CrnV2List.model_validate(raw)
                return vm_mmap

    async def get_active_vms_v1(self, crn_address: str) -> CrnV1List:
        endpoint = "/about/executions/list"

        full_url = sanitize_url(crn_address + endpoint)

        async with aiohttp.ClientSession() as session:
            async with session.get(full_url) as resp:
                resp.raise_for_status()
                raw = await resp.json()
                vm_map = CrnV1List.model_validate(raw)
                return vm_map

    async def get_active_vms(self, crn_address: str) -> Union[CrnV2List, CrnV1List]:
        try:
            return await self.get_active_vms_v2(crn_address)
        except ClientResponseError as e:
            if e.status == 404:
                return await self.get_active_vms_v1(crn_address)
            raise

    async def get_vm(
        self, crn_address: str, item_hash: ItemHash
    ) -> Optional[Union[CrnExecutionV1, CrnExecutionV2]]:
        vms = await self.get_active_vms(crn_address)

        vm_map: Dict[ItemHash, Union[CrnExecutionV1, CrnExecutionV2]] = vms.root

        if item_hash not in vm_map:
            return None

        return vm_map[item_hash]

    async def update_instance_config(self, crn_address: str, item_hash: ItemHash):
        vm = await self.get_vm(crn_address, item_hash)

        if not vm:
            raise VmNotFoundOnHost(crn_url=crn_address, item_hash=item_hash)

        # CRN have two week to upgrade their node,
        # So if the CRN does not have the update
        # We can't update config
        if isinstance(vm, CrnExecutionV1):
            raise MethodNotAvailableOnCRN()

        full_url = sanitize_url(crn_address + f"/control/{item_hash}/update")

        async with aiohttp.ClientSession() as session:
            async with session.post(full_url) as resp:
                resp.raise_for_status()
                return await resp.json()
