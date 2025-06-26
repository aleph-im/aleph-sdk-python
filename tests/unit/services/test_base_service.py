from typing import Optional
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel

from aleph.sdk.client.services.base import AggregateConfig, BaseService


class DummyModel(BaseModel):
    foo: str
    bar: Optional[int]


class DummyService(BaseService[DummyModel]):
    aggregate_key = "dummy_key"
    model_cls = DummyModel


@pytest.mark.asyncio
async def test_get_config_with_data():
    mock_client = AsyncMock()
    mock_data = {"foo": "hello", "bar": 123}
    mock_client.fetch_aggregate.return_value = mock_data

    service = DummyService(mock_client)

    result = await service.get_config("0xSOME_ADDRESS")

    assert isinstance(result, AggregateConfig)
    assert result.data is not None
    assert isinstance(result.data[0], DummyModel)
    assert result.data[0].foo == "hello"
    assert result.data[0].bar == 123


@pytest.mark.asyncio
async def test_get_config_with_no_data():
    mock_client = AsyncMock()
    mock_client.fetch_aggregate.return_value = None

    service = DummyService(mock_client)
    result = await service.get_config("0xSOME_ADDRESS")

    assert isinstance(result, AggregateConfig)
    assert result.data is None
