import logging
import math
from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional, Union

from aleph.sdk.client.services.base import BaseService

if TYPE_CHECKING:
    pass

from decimal import Decimal

from pydantic import BaseModel, RootModel

logger = logging.getLogger(__name__)


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
    credit: Optional[Decimal] = None


class ComputeUnit(BaseModel):
    vcpus: int
    memory_mib: int
    disk_mib: int


class TierComputedSpec(ComputeUnit):
    ...
    gpu_model: Optional[str]
    vram: Optional[int]


class Tier(BaseModel):
    id: str
    compute_units: int
    vram: Optional[int] = None
    model: Optional[str] = None

    def extract_tier_id(self) -> str:
        return self.id.split("-", 1)[-1]


class PricingPerEntity(BaseModel):
    price: Dict[str, Union[Price, Decimal]]
    compute_unit: Optional[ComputeUnit] = None
    tiers: Optional[List[Tier]] = None

    def _get_nb_compute_units(
        self,
        vcpus: int = 1,
        memory_mib: int = 2048,
    ) -> Optional[int]:
        if self.compute_unit:
            memory = math.ceil(memory_mib / self.compute_unit.memory_mib)
            nb_compute = vcpus if vcpus >= memory else memory
            return nb_compute
        return None

    def get_closest_tier(
        self,
        vcpus: Optional[int] = None,
        memory_mib: Optional[int] = None,
        compute_unit: Optional[int] = None,
    ):
        """Get Closest tier for Program / Instance"""

        # We Calculate Compute Unit requested based on vcpus and memory
        computed_cu = None
        if vcpus is not None and memory_mib is not None:
            computed_cu = self._get_nb_compute_units(vcpus=vcpus, memory_mib=memory_mib)
        elif vcpus is not None and self.compute_unit is not None:
            computed_cu = self._get_nb_compute_units(
                vcpus=vcpus, memory_mib=self.compute_unit.memory_mib
            )
        elif memory_mib is not None and self.compute_unit is not None:
            computed_cu = self._get_nb_compute_units(
                vcpus=self.compute_unit.vcpus, memory_mib=memory_mib
            )

        # Case where Vcpus or memory is given but also a number of CU (case on aleph-client)
        cu: Optional[int] = None
        if computed_cu is not None and compute_unit is not None:
            if computed_cu != compute_unit:
                logger.warning(
                    f"Mismatch in compute units: from CPU/RAM={computed_cu}, given={compute_unit}. "
                    f"Choosing {max(computed_cu, compute_unit)}."
                )
            cu = max(computed_cu, compute_unit)  # We trust the bigger trier
        else:
            cu = compute_unit if compute_unit is not None else computed_cu

        # now tier found
        if cu is None:
            return None

        # With CU available, choose the closest one
        candidates = self.tiers
        if candidates is None:
            return None

        best_tier = min(
            candidates,
            key=lambda t: (abs(t.compute_units - cu), -t.compute_units),
        )
        return best_tier

    def get_services_specs(
        self,
        tier: Tier,
    ) -> TierComputedSpec:
        """
        Calculate ammount of vram / cpu / disk | + gpu model / vram if it GPU instance
        """
        if self.compute_unit is None:
            raise ValueError("ComputeUnit is required to get service specs")

        cpu = tier.compute_units * self.compute_unit.vcpus
        memory_mib = tier.compute_units * self.compute_unit.memory_mib
        disk = (
            tier.compute_units * self.compute_unit.disk_mib
        )  # Min value disk can be increased

        # Gpu Specs
        gpu = None
        vram = None
        if tier.model and tier.vram:
            gpu = tier.model
            vram = tier.vram

        return TierComputedSpec(
            vcpus=cpu,
            memory_mib=memory_mib,
            disk_mib=disk,
            gpu_model=gpu,
            vram=vram,
        )


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
