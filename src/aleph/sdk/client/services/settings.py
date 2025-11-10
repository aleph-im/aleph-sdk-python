from typing import List

from pydantic import BaseModel

from .base import BaseService


class NetworkAvailableGpu(BaseModel):
    name: str
    model: str
    vendor: str
    device_id: str


class NetworkSettingsModel(BaseModel):
    compatible_gpus: List[NetworkAvailableGpu]
    last_crn_version: str
    community_wallet_address: str
    community_wallet_timestamp: int


class Settings(BaseService[NetworkSettingsModel]):
    """
    This Service handle logic around Pricing
    """

    aggregate_key = "settings"
    model_cls = NetworkSettingsModel

    def __init__(self, client):
        super().__init__(client=client)

    # Config from aggregate
    async def get_settings_aggregate(
        self,
    ) -> NetworkSettingsModel:
        result = await self.get_config(
            address="0xFba561a84A537fCaa567bb7A2257e7142701ae2A"
        )
        return result.data[0]
