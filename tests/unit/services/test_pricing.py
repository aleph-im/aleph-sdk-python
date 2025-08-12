import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.sdk.client.http import AlephHttpClient
from aleph.sdk.client.services.pricing import (
    PAYG_GROUP,
    PRICING_GROUPS,
    GroupEntity,
    Price,
    Pricing,
    PricingEntity,
    PricingModel,
    PricingPerEntity,
)


@pytest.fixture
def pricing_aggregate():
    """Load the pricing aggregate JSON file for testing."""
    json_path = Path(__file__).parent / "pricing_aggregate.json"
    with open(json_path, "r") as f:
        data = json.load(f)
    return data


@pytest.fixture
def mock_client(pricing_aggregate):
    """Create a real client with mocked HTTP responses."""
    # Create a mock response for the http session get method
    mock_response = AsyncMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = pricing_aggregate

    # Create an async context manager for the mock response
    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_response

    # Create a mock HTTP session
    mock_session = AsyncMock()
    mock_session.get = MagicMock(return_value=mock_context)

    client = AlephHttpClient(api_server="http://localhost")
    client._http_session = mock_session

    return client


@pytest.mark.asyncio
async def test_get_pricing_aggregate(mock_client):
    """Test fetching the pricing aggregate data."""
    pricing_service = Pricing(mock_client)
    result = await pricing_service.get_pricing_aggregate()

    # Check the result is a PricingModel
    assert isinstance(result, PricingModel)

    assert PricingEntity.STORAGE in result
    assert PricingEntity.PROGRAM in result
    assert PricingEntity.INSTANCE in result

    storage_entity = result[PricingEntity.STORAGE]
    assert isinstance(storage_entity, PricingPerEntity)
    assert "storage" in storage_entity.price
    storage_price = storage_entity.price["storage"]
    assert isinstance(storage_price, Price)  # Add type assertion for mypy
    assert storage_price.holding == Decimal("0.333333333")
    assert storage_entity.price["storage"].holding == Decimal("0.333333333")

    # Check program entity has correct compute unit details
    program_entity = result[PricingEntity.PROGRAM]
    assert isinstance(program_entity, PricingPerEntity)
    assert program_entity.compute_unit is not None  # Ensure compute_unit is not None
    assert program_entity.compute_unit.vcpus == 1
    assert program_entity.compute_unit.memory_mib == 2048
    assert program_entity.compute_unit.disk_mib == 2048

    # Check tiers in instance entity
    instance_entity = result[PricingEntity.INSTANCE]
    assert instance_entity.tiers is not None  # Ensure tiers is not None
    assert len(instance_entity.tiers) == 6
    assert instance_entity.tiers[0].id == "tier-1"
    assert instance_entity.tiers[0].compute_units == 1


@pytest.mark.asyncio
async def test_get_pricing_for_services(mock_client):
    """Test fetching pricing for specific services."""
    pricing_service = Pricing(mock_client)

    # Test Case 1: Get pricing for storage and program services
    services = [PricingEntity.STORAGE, PricingEntity.PROGRAM]
    result = await pricing_service.get_pricing_for_services(services)

    # Check the result contains only the requested entities
    assert len(result) == 2
    assert PricingEntity.STORAGE in result
    assert PricingEntity.PROGRAM in result
    assert PricingEntity.INSTANCE not in result

    # Verify specific pricing data
    storage_price = result[PricingEntity.STORAGE].price["storage"]
    assert isinstance(storage_price, Price)  # Ensure it's a Price object
    assert storage_price.holding == Decimal("0.333333333")

    compute_price = result[PricingEntity.PROGRAM].price["compute_unit"]
    assert isinstance(compute_price, Price)  # Ensure it's a Price object
    assert compute_price.payg == Decimal("0.011")
    assert compute_price.holding == Decimal("200")

    # Test Case 2: Using pre-fetched pricing aggregate
    pricing_info = await pricing_service.get_pricing_aggregate()
    result2 = await pricing_service.get_pricing_for_services(services, pricing_info)

    # Results should be the same
    assert result[PricingEntity.STORAGE].price == result2[PricingEntity.STORAGE].price
    assert result[PricingEntity.PROGRAM].price == result2[PricingEntity.PROGRAM].price

    # Test Case 3: Empty services list
    empty_result = await pricing_service.get_pricing_for_services([])
    assert isinstance(empty_result, dict)
    assert len(empty_result) == 0

    # Test Case 4: Web3 hosting service
    web3_result = await pricing_service.get_pricing_for_services(
        [PricingEntity.WEB3_HOSTING]
    )
    assert len(web3_result) == 1
    assert PricingEntity.WEB3_HOSTING in web3_result
    assert web3_result[PricingEntity.WEB3_HOSTING].price["fixed"] == Decimal("50")

    # Test Case 5: GPU services have specific properties
    gpu_services = [
        PricingEntity.INSTANCE_GPU_STANDARD,
        PricingEntity.INSTANCE_GPU_PREMIUM,
    ]
    gpu_result = await pricing_service.get_pricing_for_services(gpu_services)
    assert len(gpu_result) == 2
    # Check GPU models are present
    standard_tiers = gpu_result[PricingEntity.INSTANCE_GPU_STANDARD].tiers
    premium_tiers = gpu_result[PricingEntity.INSTANCE_GPU_PREMIUM].tiers
    assert standard_tiers is not None
    assert premium_tiers is not None
    assert standard_tiers[0].model == "RTX 4000 ADA"
    assert premium_tiers[1].model == "H100"


@pytest.mark.asyncio
async def test_get_pricing_for_gpu_services(mock_client):
    """Test fetching pricing for GPU services."""
    pricing_service = Pricing(mock_client)

    # Test with GPU services
    gpu_services = [
        PricingEntity.INSTANCE_GPU_STANDARD,
        PricingEntity.INSTANCE_GPU_PREMIUM,
    ]
    result = await pricing_service.get_pricing_for_services(gpu_services)

    # Check that both GPU services are returned
    assert len(result) == 2
    assert PricingEntity.INSTANCE_GPU_STANDARD in result
    assert PricingEntity.INSTANCE_GPU_PREMIUM in result

    # Verify GPU standard pricing and details
    gpu_standard = result[PricingEntity.INSTANCE_GPU_STANDARD]
    compute_unit_price = gpu_standard.price["compute_unit"]
    assert isinstance(compute_unit_price, Price)
    assert compute_unit_price.payg == Decimal("0.28")

    standard_tiers = gpu_standard.tiers
    assert standard_tiers is not None
    assert len(standard_tiers) == 5
    assert standard_tiers[0].model == "RTX 4000 ADA"
    assert standard_tiers[0].vram == 20480

    # Verify GPU premium pricing and details
    gpu_premium = result[PricingEntity.INSTANCE_GPU_PREMIUM]
    premium_compute_price = gpu_premium.price["compute_unit"]
    assert isinstance(premium_compute_price, Price)
    assert premium_compute_price.payg == Decimal("0.56")

    premium_tiers = gpu_premium.tiers
    assert premium_tiers is not None
    assert len(premium_tiers) == 2
    assert premium_tiers[1].model == "H100"
    assert premium_tiers[1].vram == 81920


@pytest.mark.asyncio
async def test_pricing_groups():
    """Test the pricing groups constants."""
    # Check that all pricing entities are covered in PRICING_GROUPS
    all_entities = set()
    for group_entities in PRICING_GROUPS.values():
        for entity in group_entities:
            all_entities.add(entity)

    # All PricingEntity values should be in some group
    for entity in PricingEntity:
        assert entity in all_entities

    # Check ALL group contains all entities
    assert set(PRICING_GROUPS[GroupEntity.ALL]) == set(PricingEntity)

    # Check PAYG_GROUP contains expected entities
    assert PricingEntity.INSTANCE in PAYG_GROUP
    assert PricingEntity.INSTANCE_CONFIDENTIAL in PAYG_GROUP
    assert PricingEntity.INSTANCE_GPU_STANDARD in PAYG_GROUP
    assert PricingEntity.INSTANCE_GPU_PREMIUM in PAYG_GROUP
