from typing import TYPE_CHECKING, Dict, List, Optional, Union

import aiohttp
from aiohttp.client_exceptions import ClientResponseError
from aleph_message.models import ItemHash
from pydantic import BaseModel

from aleph.sdk.conf import settings
from aleph.sdk.exceptions import MethodNotAvailableOnCRN, VmNotFoundOnHost
from aleph.sdk.types import (
    CrnExecutionV1,
    CrnExecutionV2,
    CrnV1List,
    CrnV2List,
    DictLikeModel,
)
from aleph.sdk.utils import extract_valid_eth_address, sanitize_url

if TYPE_CHECKING:
    from aleph.sdk.client.http import AlephHttpClient


class GPU(BaseModel):
    vendor: str
    model: str
    device_name: str
    device_class: str
    pci_host: str
    compatible: bool


class NetworkGPUS(BaseModel):
    total_gpu_count: int
    available_gpu_count: int
    available_gpu_list: dict[str, List[GPU]]  # str = node_url
    used_gpu_list: dict[str, List[GPU]]  # str = node_url


class CRN(DictLikeModel):
    # This Model work as dict but where we can type what we need / apply logic on top

    # Simplify search
    hash: str
    name: str
    address: str

    gpu_support: Optional[bool] = False
    confidential_support: Optional[bool] = False
    qemu_support: Optional[bool] = False

    version: Optional[str] = "0.0.0"
    payment_receiver_address: Optional[str]  # Can be None if not configured


class CrnList(DictLikeModel):
    crns: list[CRN] = []

    @classmethod
    def from_api(cls, payload: dict) -> "CrnList":
        raw_list = payload.get("crns", [])
        crn_list = [
            CRN.model_validate(item) if not isinstance(item, CRN) else item
            for item in raw_list
        ]
        return cls(crns=crn_list)

    def find_gpu_on_network(self):
        gpu_count: int = 0
        available_gpu_count: int = 0

        compatible_gpu: Dict[str, List[GPU]] = {}
        available_compatible_gpu: Dict[str, List[GPU]] = {}

        for crn_ in self.crns:
            if not crn_.gpu_support:
                continue

            # Extracts used GPU
            for gpu in crn_.get("compatible_gpus", []):
                compatible_gpu[crn_.address] = []
                compatible_gpu[crn_.address].append(GPU.model_validate(gpu))
                gpu_count += 1

            # Extracts available GPU
            for gpu in crn_.get("compatible_available_gpus", []):
                available_compatible_gpu[crn_.address] = []
                available_compatible_gpu[crn_.address].append(GPU.model_validate(gpu))
                gpu_count += 1
                available_gpu_count += 1

        return NetworkGPUS(
            total_gpu_count=gpu_count,
            available_gpu_count=available_gpu_count,
            used_gpu_list=compatible_gpu,
            available_gpu_list=available_compatible_gpu,
        )

    def filter_crn(
        self,
        latest_crn_version: bool = False,
        ipv6: bool = False,
        stream_address: bool = False,
        confidential: bool = False,
        gpu: bool = False,
    ) -> list[CRN]:
        """Filter compute resource node list, unfiltered by default.
        Args:
            latest_crn_version (bool): Filter by latest crn version.
            ipv6 (bool): Filter invalid IPv6 configuration.
            stream_address (bool): Filter invalid payment receiver address.
            confidential (bool): Filter by confidential computing support.
            gpu (bool): Filter by GPU support.
        Returns:
            list[CRN]: List of compute resource nodes. (if no filter applied, return all)
        """
        # current_crn_version = await fetch_latest_crn_version()
        # Relax current filter to allow use aleph-vm versions since 1.5.1.
        # TODO: Allow to specify that option on settings aggregate on maybe on GitHub
        current_crn_version = "1.5.1"

        filtered_crn: list[CRN] = []
        for crn_ in self.crns:
            # Check crn version
            if latest_crn_version and (crn_.version or "0.0.0") < current_crn_version:
                continue

            # Filter with ipv6 check
            if ipv6:
                ipv6_check = crn_.get("ipv6_check")
                if not ipv6_check or not all(ipv6_check.values()):
                    continue

            if stream_address and not extract_valid_eth_address(
                crn_.payment_receiver_address or ""
            ):
                continue

            # Confidential Filter
            if confidential and not crn_.confidential_support:
                continue

            # Filter with GPU / Available GPU
            available_gpu = crn_.get("compatible_available_gpus")
            if gpu and (not crn_.gpu_support or not available_gpu):
                continue

            filtered_crn.append(crn_)
        return filtered_crn

    # Find CRN by address
    def find_crn_by_address(self, address: str) -> Optional[CRN]:
        for crn_ in self.crns:
            if crn_.address == sanitize_url(address):
                return crn_
        return None

    # Find CRN by hash
    def find_crn_by_hash(self, crn_hash: str) -> Optional[CRN]:
        for crn_ in self.crns:
            if crn_.hash == crn_hash:
                return crn_
        return None

    def find_crn(
        self,
        address: Optional[str] = None,
        crn_hash: Optional[str] = None,
    ) -> Optional[CRN]:
        """Find CRN by address or hash (both optional, address priority)

        Args:
            address (Optional[str], optional): url of the node. Defaults to None.
            crn_hash (Optional[str], optional): hash of the nodes. Defaults to None.

        Returns:
            Optional[CRN]: CRN object or None if not found
        """
        if address:
            return self.find_crn_by_address(address)
        if crn_hash:
            return self.find_crn_by_hash(crn_hash)
        return None


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

    async def get_crns_list(self, only_active: bool = True) -> CrnList:
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
        # Convert bool to string for the query parameter
        filter_inactive_str = str(only_active).lower()
        params = {"filter_inactive": filter_inactive_str}

        # Create a new session for external domain requests
        async with aiohttp.ClientSession() as session:
            async with session.get(
                sanitize_url(settings.CRN_LIST_URL), params=params
            ) as resp:
                resp.raise_for_status()
                return CrnList.from_api(await resp.json())

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

    # Gpu Functions Helper
    async def fetch_gpu_on_network(
        self,
        only_active: bool = True,
    ) -> NetworkGPUS:
        crn_list = await self.get_crns_list(only_active)
        return crn_list.find_gpu_on_network()
