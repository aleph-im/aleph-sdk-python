from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph_message.models import ItemHash

from aleph.sdk.client.services.crn import Crn
from aleph.sdk.exceptions import MethodNotAvailableOnCRN
from aleph.sdk.types import CrnExecutionV1, CrnExecutionV2, CrnV1List, CrnV2List

from .mocks import (
    FAKE_CRN_BASIC_HASH,
    FAKE_CRN_BASIC_URL,
    FAKE_CRN_CONF_HASH,
    FAKE_CRN_GPU_HASH,
    make_mock_aiohttp_session,
    make_mock_get_active_vms_parametrized,
)


@pytest.fixture
def mocked_crn_list_call(mock_crn_list):
    """Create a mock CRN list in the structure expected by the API response."""
    return {"crns": mock_crn_list}


@pytest.mark.asyncio
async def test_crn_get_last_crn_version():
    """Test the CrnService get_last_crn_version method"""
    mock_client = AsyncMock()
    crn_service = Crn(mock_client)
    mock_session = make_mock_aiohttp_session({"tag_name": "1.5.0"})

    with patch(
        "aleph.sdk.client.services.crn.aiohttp.ClientSession", return_value=mock_session
    ):
        result = await crn_service.get_last_crn_version()

    assert result == "1.5.0"


@pytest.mark.asyncio
async def test_crn_get_crns_list(mocked_crn_list_call):
    mock_session = make_mock_aiohttp_session(mocked_crn_list_call)

    with patch(
        "aleph.sdk.client.services.crn.aiohttp.ClientSession", return_value=mock_session
    ):
        mock_client = AsyncMock()
        crn_service = Crn(mock_client)
        result = await crn_service.get_crns_list()

    assert len(result["crns"]) == 3
    assert result["crns"][0]["hash"] == FAKE_CRN_GPU_HASH
    assert result["crns"][1]["hash"] == FAKE_CRN_CONF_HASH
    assert result["crns"][2]["hash"] == FAKE_CRN_BASIC_HASH


@pytest.mark.asyncio
async def test_crn_active_vms_v2(vm_status_v2):
    mock_client = MagicMock()
    crn_service = Crn(mock_client)

    mock_session = make_mock_aiohttp_session(vm_status_v2)
    with patch(
        "aleph.sdk.client.services.crn.aiohttp.ClientSession", return_value=mock_session
    ):
        vm = await crn_service.get_active_vms_v2(FAKE_CRN_BASIC_URL)
        assert (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            in vm.root
        )
        assert (
            vm.root[
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ].networking.ipv4_network
            == "192.168.0.0/24"
        )


@pytest.mark.asyncio
async def test_crn_service_get_active_vms_v1(vm_status_v1):
    """Test the CrnService get_active_vms_v1 method"""
    mock_client = MagicMock()
    crn_service = Crn(mock_client)

    mock_session_context = make_mock_aiohttp_session(vm_status_v1)

    with patch(
        "aleph.sdk.client.services.crn.aiohttp.ClientSession",
        return_value=mock_session_context,
    ):
        result = await crn_service.get_active_vms_v1("https://crn.example.com")
        assert (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            in result.root
        )
        assert (
            result.root[
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ].networking.ipv4
            == "192.168.0.1"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "v2_fails, expected_type, payload_fixture_name",
    [
        (False, CrnV2List, "vm_status_v2"),
        (True, CrnV1List, "vm_status_v1"),
    ],
)
async def test_crn_get_active_vms_parametrized(
    v2_fails, expected_type, payload_fixture_name, request
):

    expected_payload = request.getfixturevalue(payload_fixture_name)

    # Create a session that handles the v1/v2 fallback logic correctly
    mock_session = make_mock_get_active_vms_parametrized(v2_fails, expected_payload)

    with patch(
        "aleph.sdk.client.services.crn.aiohttp.ClientSession", return_value=mock_session
    ):
        crn_service = Crn(MagicMock())
        result = await crn_service.get_active_vms(FAKE_CRN_BASIC_URL)
        assert isinstance(result, expected_type)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "v2_fails, expected_type, payload_fixture_name",
    [
        (False, CrnExecutionV2, "vm_status_v2"),
        (True, CrnExecutionV1, "vm_status_v1"),
    ],
)
async def test_crn_get_vms_parametrized(
    v2_fails, expected_type, payload_fixture_name, request
):
    expected_payload = request.getfixturevalue(payload_fixture_name)

    # Create a session that handles the v1/v2 fallback logic correctly
    mock_session = make_mock_get_active_vms_parametrized(v2_fails, expected_payload)

    with patch(
        "aleph.sdk.client.services.crn.aiohttp.ClientSession", return_value=mock_session
    ):
        crn_service = Crn(MagicMock())
        result = await crn_service.get_vm(
            crn_address=FAKE_CRN_BASIC_URL,
            item_hash=ItemHash(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
        )
        assert isinstance(result, expected_type)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "v2_fails, payload_fixture_name",
    [
        (False, "vm_status_v2"),
        (True, "vm_status_v1"),
    ],
)
async def test_crn_update_instance_config(v2_fails, payload_fixture_name, request):
    expected_payload = request.getfixturevalue(payload_fixture_name)
    mock_session = make_mock_get_active_vms_parametrized(v2_fails, expected_payload)

    with patch(
        "aleph.sdk.client.services.crn.aiohttp.ClientSession", return_value=mock_session
    ):
        crn_service = Crn(MagicMock())
        item_hash = ItemHash(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )

        if v2_fails:
            with pytest.raises(MethodNotAvailableOnCRN):
                await crn_service.update_instance_config("address", item_hash)
        else:
            result = await crn_service.update_instance_config("address", item_hash)
            assert result["status"]
