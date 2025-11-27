from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.sdk import AlephHttpClient
from aleph.sdk.client.services.settings import NetworkSettingsModel, Settings


@pytest.fixture
def mock_settings_aggregate_response():
    return {
        "compatible_gpus": [
            {
                "name": "AD102GL [L40S]",
                "model": "L40S",
                "vendor": "NVIDIA",
                "device_id": "10de:26b9",
            },
            {
                "name": "GB202 [GeForce RTX 5090]",
                "model": "RTX 5090",
                "vendor": "NVIDIA",
                "device_id": "10de:2685",
            },
            {
                "name": "GB202 [GeForce RTX 5090 D]",
                "model": "RTX 5090",
                "vendor": "NVIDIA",
                "device_id": "10de:2687",
            },
            {
                "name": "AD102 [GeForce RTX 4090]",
                "model": "RTX 4090",
                "vendor": "NVIDIA",
                "device_id": "10de:2684",
            },
            {
                "name": "AD102 [GeForce RTX 4090 D]",
                "model": "RTX 4090",
                "vendor": "NVIDIA",
                "device_id": "10de:2685",
            },
            {
                "name": "GA102 [GeForce RTX 3090]",
                "model": "RTX 3090",
                "vendor": "NVIDIA",
                "device_id": "10de:2204",
            },
            {
                "name": "GA102 [GeForce RTX 3090 Ti]",
                "model": "RTX 3090",
                "vendor": "NVIDIA",
                "device_id": "10de:2203",
            },
            {
                "name": "AD104GL [RTX 4000 SFF Ada Generation]",
                "model": "RTX 4000 ADA",
                "vendor": "NVIDIA",
                "device_id": "10de:27b0",
            },
            {
                "name": "AD104GL [RTX 4000 Ada Generation]",
                "model": "RTX 4000 ADA",
                "vendor": "NVIDIA",
                "device_id": "10de:27b2",
            },
            {
                "name": "GA102GL [RTX A5000]",
                "model": "RTX A5000",
                "vendor": "NVIDIA",
                "device_id": "10de:2231",
            },
            {
                "name": "GA102GL [RTX A6000]",
                "model": "RTX A6000",
                "vendor": "NVIDIA",
                "device_id": "10de:2230",
            },
            {
                "name": "GH100 [H100]",
                "model": "H100",
                "vendor": "NVIDIA",
                "device_id": "10de:2336",
            },
            {
                "name": "GH100 [H100 NVSwitch]",
                "model": "H100",
                "vendor": "NVIDIA",
                "device_id": "10de:22a3",
            },
            {
                "name": "GH100 [H100 CNX]",
                "model": "H100",
                "vendor": "NVIDIA",
                "device_id": "10de:2313",
            },
            {
                "name": "GH100 [H100 SXM5 80GB]",
                "model": "H100",
                "vendor": "NVIDIA",
                "device_id": "10de:2330",
            },
            {
                "name": "GH100 [H100 PCIe]",
                "model": "H100",
                "vendor": "NVIDIA",
                "device_id": "10de:2331",
            },
            {
                "name": "GA100",
                "model": "A100",
                "vendor": "NVIDIA",
                "device_id": "10de:2080",
            },
            {
                "name": "GA100",
                "model": "A100",
                "vendor": "NVIDIA",
                "device_id": "10de:2081",
            },
            {
                "name": "GA100 [A100 SXM4 80GB]",
                "model": "A100",
                "vendor": "NVIDIA",
                "device_id": "10de:20b2",
            },
            {
                "name": "GA100 [A100 PCIe 80GB]",
                "model": "A100",
                "vendor": "NVIDIA",
                "device_id": "10de:20b5",
            },
            {
                "name": "GA100 [A100X]",
                "model": "A100",
                "vendor": "NVIDIA",
                "device_id": "10de:20b8",
            },
            {
                "name": "GH100 [H200 SXM 141GB]",
                "model": "H200",
                "vendor": "NVIDIA",
                "device_id": "10de:2335",
            },
            {
                "name": "GH100 [H200 NVL]",
                "model": "H200",
                "vendor": "NVIDIA",
                "device_id": "10de:233b",
            },
            {
                "name": "AD102GL [RTX 6000 ADA]",
                "model": "RTX 6000 ADA",
                "vendor": "NVIDIA",
                "device_id": "10de:26b1",
            },
        ],
        "last_crn_version": "1.7.2",
        "community_wallet_address": "0x5aBd3258C5492fD378EBC2e0017416E199e5Da56",
        "community_wallet_timestamp": 1739996239,
    }


@pytest.mark.asyncio
async def test_get_settings_aggregate(
    make_mock_aiohttp_session, mock_settings_aggregate_response
):
    client = AlephHttpClient(api_server="http://localhost")

    # Properly mock the fetch_aggregate method using monkeypatch
    client._http_session = MagicMock()
    monkeypatch = AsyncMock(return_value=mock_settings_aggregate_response)
    setattr(client, "fetch_aggregate", monkeypatch)

    settings_service = Settings(client)
    result = await settings_service.get_settings_aggregate()

    assert isinstance(result, NetworkSettingsModel)
    assert len(result.compatible_gpus) == 24  # We have 24 GPUs in the mock data

    rtx4000_gpu = next(
        gpu for gpu in result.compatible_gpus if gpu.device_id == "10de:27b0"
    )
    assert rtx4000_gpu.name == "AD104GL [RTX 4000 SFF Ada Generation]"
    assert rtx4000_gpu.model == "RTX 4000 ADA"
    assert rtx4000_gpu.vendor == "NVIDIA"

    assert result.last_crn_version == "1.7.2"
    assert (
        result.community_wallet_address == "0x5aBd3258C5492fD378EBC2e0017416E199e5Da56"
    )
    assert result.community_wallet_timestamp == 1739996239

    # Verify that fetch_aggregate was called with the correct parameters
    assert monkeypatch.call_count == 1
    assert (
        monkeypatch.call_args.kwargs["address"]
        == "0xFba561a84A537fCaa567bb7A2257e7142701ae2A"
    )
    assert monkeypatch.call_args.kwargs["key"] == "settings"
