from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional, Union

from aleph.sdk.client.services.base import BaseService

if TYPE_CHECKING:
    pass

from decimal import Decimal

from pydantic import BaseModel, RootModel


class PricingEntity(str, Enum):
    STORAGE = "storage"
    WEB3_HOSTING = "web3_hosting"
    PROGRAM = "program"
    PROGRAM_PERSISTENT = "program_persistent"
    INSTANCE = "instance"
    INSTANCE_CONFIDENTIAL = "instance_confidential"
    INSTANCE_GPU_STANDARD = "instance_gpu_standard"
    INSTANCE_GPU_PREMIUM = "instance_gpu_premium"


class GroupEntity(str, Enum):
    STORAGE = "storage"
    WEBSITE = "website"
    PROGRAM = "program"
    INSTANCE = "instance"
    CONFIDENTIAL = "confidential"
    GPU = "gpu"
    ALL = "all"


class Price(BaseModel):
    payg: Optional[Decimal] = None
    holding: Optional[Decimal] = None
    fixed: Optional[Decimal] = None


class ComputeUnit(BaseModel):
    vcpus: int
    memory_mib: int
    disk_mib: int


class Tier(BaseModel):
    id: str
    compute_units: int
    vram: Optional[int] = None
    model: Optional[str] = None


class PricingPerEntity(BaseModel):
    price: Dict[str, Union[Price, Decimal]]
    compute_unit: Optional[ComputeUnit] = None
    tiers: Optional[List[Tier]] = None


class PricingModel(RootModel[Dict[PricingEntity, PricingPerEntity]]):
    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, item):
        return self.root[item]


PRICING_GROUPS: dict[str, list[PricingEntity]] = {
    GroupEntity.STORAGE: [PricingEntity.STORAGE],
    GroupEntity.WEBSITE: [PricingEntity.WEB3_HOSTING],
    GroupEntity.PROGRAM: [PricingEntity.PROGRAM, PricingEntity.PROGRAM_PERSISTENT],
    GroupEntity.INSTANCE: [PricingEntity.INSTANCE],
    GroupEntity.CONFIDENTIAL: [PricingEntity.INSTANCE_CONFIDENTIAL],
    GroupEntity.GPU: [
        PricingEntity.INSTANCE_GPU_STANDARD,
        PricingEntity.INSTANCE_GPU_PREMIUM,
    ],
    GroupEntity.ALL: list(PricingEntity),
}

PAYG_GROUP: list[PricingEntity] = [
    PricingEntity.INSTANCE,
    PricingEntity.INSTANCE_CONFIDENTIAL,
    PricingEntity.INSTANCE_GPU_STANDARD,
    PricingEntity.INSTANCE_GPU_PREMIUM,
]


class Pricing(BaseService[PricingModel]):
    """
    This Service handle logic around Pricing
    """

    aggregate_key = "pricing"
    model_cls = PricingModel

    def __init__(self, client):
        super().__init__(client=client)

    # Config from aggregate
    async def get_pricing_aggregate(
        self,
    ) -> PricingModel:
        result = await self.get_config(
            address="0xFba561a84A537fCaa567bb7A2257e7142701ae2A"
        )
        return result.data[0]

    async def get_pricing_for_services(
        self, services: List[PricingEntity], pricing_info: Optional[PricingModel] = None
    ) -> Dict[PricingEntity, PricingPerEntity]:
        """
        Get pricing information for requested services

        Args:
            services: List of pricing entities to get information for
            pricing_info: Optional pre-fetched pricing aggregate

        Returns:
            Dictionary with pricing information for requested services
        """
        if (
            not pricing_info
        ):  # Avoid reloading aggregate info if there is already fetched
            pricing_info = await self.get_pricing_aggregate()

        result = {}
        for service in services:
            if service in pricing_info:
                result[service] = pricing_info[service]

        return result
