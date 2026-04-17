from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.sdk.client.http import AlephHttpClient
from aleph.sdk.client.services.runtimes import (
    RuntimeEntry,
    RuntimesAggregate,
    RuntimeType,
    Runtimes,
)

MOCK_AGGREGATE = {
    "data": {
        "runtimes": {
            "entries": [
                {
                    "id": "debian-12-qemu",
                    "name": "Debian 12",
                    "type": "instance",
                    "item_hash": "aaa111",
                    "default": True,
                },
                {
                    "id": "debian-13-rescue",
                    "name": "Debian 13 (Rescue)",
                    "type": "rescue",
                    "item_hash": "bbb222",
                    "sha256": "ccc333",
                    "default": True,
                },
                {
                    "id": "ubuntu-24-rescue",
                    "name": "Ubuntu 24.04 (Rescue)",
                    "type": "rescue",
                    "item_hash": "ddd444",
                    "default": False,
                },
                {
                    "id": "ovmf-sev",
                    "name": "OVMF SEV Firmware",
                    "type": "firmware",
                    "item_hash": "eee555",
                    "firmware_hash": "fff666",
                    "default": True,
                },
            ]
        }
    }
}


@pytest.fixture
def mock_client():
    mock_response = AsyncMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = MOCK_AGGREGATE

    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_response

    mock_session = AsyncMock()
    mock_session.get = MagicMock(return_value=mock_context)

    client = AlephHttpClient(api_server="http://localhost")
    client._http_session = mock_session

    return client


@pytest.mark.asyncio
async def test_get_runtimes_aggregate(mock_client):
    service = Runtimes(mock_client)
    result = await service.get_runtimes_aggregate()

    assert isinstance(result, RuntimesAggregate)
    assert len(result.entries) == 4


@pytest.mark.asyncio
async def test_get_runtimes_all(mock_client):
    service = Runtimes(mock_client)
    entries = await service.get_runtimes()

    assert len(entries) == 4
    assert all(isinstance(e, RuntimeEntry) for e in entries)


@pytest.mark.asyncio
async def test_get_runtimes_filtered_by_type(mock_client):
    service = Runtimes(mock_client)

    rescue = await service.get_runtimes(RuntimeType.RESCUE)
    assert len(rescue) == 2
    assert all(e.type == RuntimeType.RESCUE for e in rescue)

    instance = await service.get_runtimes(RuntimeType.INSTANCE)
    assert len(instance) == 1
    assert instance[0].id == "debian-12-qemu"

    firmware = await service.get_runtimes(RuntimeType.FIRMWARE)
    assert len(firmware) == 1
    assert firmware[0].firmware_hash == "fff666"


@pytest.mark.asyncio
async def test_get_default_runtime(mock_client):
    service = Runtimes(mock_client)

    default_rescue = await service.get_default_runtime(RuntimeType.RESCUE)
    assert default_rescue is not None
    assert default_rescue.id == "debian-13-rescue"
    assert default_rescue.default is True
    assert default_rescue.sha256 == "ccc333"

    default_instance = await service.get_default_runtime(RuntimeType.INSTANCE)
    assert default_instance is not None
    assert default_instance.id == "debian-12-qemu"


@pytest.mark.asyncio
async def test_get_default_runtime_none_when_no_default(mock_client):
    service = Runtimes(mock_client)

    default_program = await service.get_default_runtime(RuntimeType.PROGRAM)
    assert default_program is None


@pytest.mark.asyncio
async def test_get_runtimes_aggregate_empty():
    """Test handling of empty/missing aggregate data."""
    mock_response = AsyncMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"data": {"runtimes": None}}

    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_response

    mock_session = AsyncMock()
    mock_session.get = MagicMock(return_value=mock_context)

    client = AlephHttpClient(api_server="http://localhost")
    client._http_session = mock_session

    service = Runtimes(client)
    result = await service.get_runtimes_aggregate()

    assert isinstance(result, RuntimesAggregate)
    assert len(result.entries) == 0


@pytest.mark.asyncio
async def test_runtime_type_enum():
    assert RuntimeType.PROGRAM == "program"
    assert RuntimeType.INSTANCE == "instance"
    assert RuntimeType.RESCUE == "rescue"
    assert RuntimeType.FIRMWARE == "firmware"
