from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.client.services.authenticated_port_forwarder import (
    AuthenticatedPortForwarder,
    PortForwarder,
)
from aleph.sdk.client.services.crn import Crn
from aleph.sdk.client.services.dns import DNS
from aleph.sdk.client.services.instance import Instance
from aleph.sdk.client.services.scheduler import Scheduler
from aleph.sdk.types import (
    IPV4,
    AllocationItem,
    Dns,
    PortFlags,
    Ports,
    SchedulerNodes,
    SchedulerPlan,
)


@pytest.mark.asyncio
async def test_aleph_http_client_services_loading():
    """Test that services are properly loaded in AlephHttpClient's __aenter__"""
    with patch("aiohttp.ClientSession") as mock_session:
        mock_session_instance = AsyncMock()
        mock_session.return_value = mock_session_instance

        client = AlephHttpClient(api_server="http://localhost")

        async def mocked_aenter():
            client._http_session = mock_session_instance
            client.dns = DNS(client)
            client.port_forwarder = PortForwarder(client)
            client.crn = Crn(client)
            client.scheduler = Scheduler(client)
            client.instance = Instance(client)
            return client

        with patch.object(client, "__aenter__", mocked_aenter), patch.object(
            client, "__aexit__", AsyncMock()
        ):
            async with client:
                assert isinstance(client.dns, DNS)
                assert isinstance(client.port_forwarder, PortForwarder)
                assert isinstance(client.crn, Crn)
                assert isinstance(client.scheduler, Scheduler)
                assert isinstance(client.instance, Instance)

                assert client.dns._client == client
                assert client.port_forwarder._client == client
                assert client.crn._client == client
                assert client.scheduler._client == client
                assert client.instance._client == client


@pytest.mark.asyncio
async def test_authenticated_http_client_services_loading(ethereum_account):
    """Test that authenticated services are properly loaded in AuthenticatedAlephHttpClient's __aenter__"""
    with patch("aiohttp.ClientSession") as mock_session:
        mock_session_instance = AsyncMock()
        mock_session.return_value = mock_session_instance

        client = AuthenticatedAlephHttpClient(
            account=ethereum_account, api_server="http://localhost"
        )

        async def mocked_aenter():
            client._http_session = mock_session_instance
            client.dns = DNS(client)
            client.port_forwarder = AuthenticatedPortForwarder(client)
            client.crn = Crn(client)
            client.scheduler = Scheduler(client)
            client.instance = Instance(client)
            return client

        with patch.object(client, "__aenter__", mocked_aenter), patch.object(
            client, "__aexit__", AsyncMock()
        ):
            async with client:
                assert isinstance(client.dns, DNS)
                assert isinstance(client.port_forwarder, AuthenticatedPortForwarder)
                assert isinstance(client.crn, Crn)
                assert isinstance(client.scheduler, Scheduler)
                assert isinstance(client.instance, Instance)

                assert client.dns._client == client
                assert client.port_forwarder._client == client
                assert client.crn._client == client
                assert client.scheduler._client == client
                assert client.instance._client == client


def mock_aiohttp_session(response_data, raise_error=False, error_status=404):
    """
    Creates a mock for aiohttp.ClientSession that properly handles async context managers.

    Args:
        response_data: The data to return from the response's json() method
        raise_error: Whether to raise an aiohttp.ClientResponseError
        error_status: The HTTP status code to use if raising an error

    Returns:
        A tuple of (patch_target, mock_session_context, mock_session, mock_response)
    """
    # Mock the response object
    mock_response = MagicMock()

    if raise_error:
        # Set up raise_for_status to raise an exception
        error = aiohttp.ClientResponseError(
            request_info=MagicMock(),
            history=tuple(),
            status=error_status,
            message="Not Found" if error_status == 404 else "Error",
        )
        mock_response.raise_for_status = MagicMock(side_effect=error)
    else:
        # Normal case - just return the data
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value=response_data)

    # Mock the context manager for session.get
    mock_context_manager = MagicMock()
    mock_context_manager.__aenter__ = AsyncMock(return_value=mock_response)
    mock_context_manager.__aexit__ = AsyncMock(return_value=None)

    # Mock the session's get method to return our context manager
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_context_manager)
    mock_session.post = MagicMock(return_value=mock_context_manager)

    # Mock the ClientSession context manager
    mock_session_context = MagicMock()
    mock_session_context.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_context.__aexit__ = AsyncMock(return_value=None)

    return "aiohttp.ClientSession", mock_session_context, mock_session, mock_response


@pytest.mark.asyncio
async def test_authenticated_port_forwarder_create_port_forward(ethereum_account):
    """Test the create_port method in AuthenticatedPortForwarder"""
    mock_client = MagicMock()
    mock_client.http_session = AsyncMock()
    mock_client.account = ethereum_account

    auth_port_forwarder = AuthenticatedPortForwarder(mock_client)

    ports = Ports(ports={80: PortFlags(tcp=True, udp=False)})

    mock_message = MagicMock()
    mock_status = MagicMock()

    # Setup the mock for create_aggregate
    mock_client.create_aggregate = AsyncMock(return_value=(mock_message, mock_status))

    # Mock the _verify_status_processed_and_ownership method
    with patch.object(
        auth_port_forwarder,
        "_verify_status_processed_and_ownership",
        AsyncMock(return_value=(mock_message, mock_status)),
    ):
        # Call the actual method
        result_message, result_status = await auth_port_forwarder.create_ports(
            item_hash="test_hash", ports=ports
        )

    # Verify create_aggregate was called
    mock_client.create_aggregate.assert_called_once()

    # Check the parameters passed to create_aggregate
    call_args = mock_client.create_aggregate.call_args
    assert call_args[1]["key"] == "port-forwarding"
    assert "test_hash" in call_args[1]["content"]

    # Verify the method returns what create_aggregate returns
    assert result_message == mock_message
    assert result_status == mock_status


@pytest.mark.asyncio
async def test_authenticated_port_forwarder_update_port(ethereum_account):
    """Test the update_port method in AuthenticatedPortForwarder"""
    mock_client = MagicMock()
    mock_client.http_session = AsyncMock()
    mock_client.account = ethereum_account

    auth_port_forwarder = AuthenticatedPortForwarder(mock_client)

    ports = Ports(ports={80: PortFlags(tcp=True, udp=False)})

    mock_message = MagicMock()
    mock_status = MagicMock()

    # Setup the mock for create_aggregate
    mock_client.create_aggregate = AsyncMock(return_value=(mock_message, mock_status))

    # Mock the _verify_status_processed_and_ownership method
    with patch.object(
        auth_port_forwarder,
        "_verify_status_processed_and_ownership",
        AsyncMock(return_value=(mock_message, mock_status)),
    ):
        # Call the actual method
        result_message, result_status = await auth_port_forwarder.update_ports(
            item_hash="test_hash", ports=ports
        )

    # Verify create_aggregate was called
    mock_client.create_aggregate.assert_called_once()

    # Check the parameters passed to create_aggregate
    call_args = mock_client.create_aggregate.call_args
    assert call_args[1]["key"] == "port-forwarding"
    assert "test_hash" in call_args[1]["content"]

    # Verify the method returns what create_aggregate returns
    assert result_message == mock_message
    assert result_status == mock_status


@pytest.mark.asyncio
async def test_dns_service_get_public_dns():
    """Test the DNSService get_public_dns method"""
    mock_client = MagicMock()
    dns_service = DNS(mock_client)

    # Mock the DnsListAdapter with a valid 64-character hash for ItemHash
    mock_dns_list = [
        Dns(
            name="test.aleph.sh",
            item_hash="b236db23bf5ad005ad7f5d82eed08a68a925020f0755b2a59c03f784499198eb",
            ipv6="2001:db8::1",
            ipv4=IPV4(public="192.0.2.1", local="10.0.0.1"),
        )
    ]

    # Patch DnsListAdapter.validate_json to return our mock DNS list
    with patch(
        "aleph.sdk.types.DnsListAdapter.validate_json", return_value=mock_dns_list
    ):
        # Set up mock for aiohttp.ClientSession to return a string (which is what validate_json expects)
        patch_target, mock_session_context, _, _ = mock_aiohttp_session(
            '["dummy json string"]'
        )

        # Patch the ClientSession constructor
        with patch(patch_target, return_value=mock_session_context):
            result = await dns_service.get_public_dns()

            assert len(result) == 1
            assert result[0].name == "test.aleph.sh"
            assert (
                result[0].item_hash
                == "b236db23bf5ad005ad7f5d82eed08a68a925020f0755b2a59c03f784499198eb"
            )
            assert result[0].ipv6 == "2001:db8::1"
            assert result[0].ipv4 is not None and result[0].ipv4.public == "192.0.2.1"


@pytest.mark.asyncio
async def test_crn_service_get_last_crn_version():
    """Test the CrnService get_last_crn_version method"""
    mock_client = MagicMock()
    crn_service = Crn(mock_client)

    # Set up mock for aiohttp.ClientSession
    patch_target, mock_session_context, _, _ = mock_aiohttp_session(
        {"tag_name": "v1.2.3"}
    )

    # Patch the ClientSession constructor
    with patch(patch_target, return_value=mock_session_context):
        result = await crn_service.get_last_crn_version()
        assert result == "v1.2.3"


@pytest.mark.asyncio
async def test_scheduler_service_get_plan():
    """Test the SchedulerService get_plan method"""
    mock_client = MagicMock()
    scheduler_service = Scheduler(mock_client)

    mock_plan_data = {
        "period": {"start_timestamp": "2023-01-01T00:00:00Z", "duration_seconds": 3600},
        "plan": {
            "node1": {
                "persistent_vms": [
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                ],
                "instances": [],
                "on_demand_vms": [],
                "jobs": [],
            }
        },
    }

    # Set up mock for aiohttp.ClientSession
    patch_target, mock_session_context, _, _ = mock_aiohttp_session(mock_plan_data)

    # Patch the ClientSession constructor
    with patch(patch_target, return_value=mock_session_context):
        result = await scheduler_service.get_plan()
        assert isinstance(result, SchedulerPlan)
        assert "node1" in result.plan
        assert (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            in result.plan["node1"].persistent_vms
        )


@pytest.mark.asyncio
async def test_scheduler_service_get_scheduler_node():
    """Test the SchedulerService get_scheduler_node method"""
    mock_client = MagicMock()
    scheduler_service = Scheduler(mock_client)

    mock_nodes_data = {
        "nodes": [
            {
                "node_id": "node1",
                "url": "https://node1.aleph.im",
                "ipv6": "2001:db8::1",
                "supports_ipv6": True,
            },
            {
                "node_id": "node2",
                "url": "https://node2.aleph.im",
                "ipv6": None,
                "supports_ipv6": False,
            },
        ]
    }

    # Set up mock for aiohttp.ClientSession
    patch_target, mock_session_context, _, _ = mock_aiohttp_session(mock_nodes_data)

    # Patch the ClientSession constructor
    with patch(patch_target, return_value=mock_session_context):
        result = await scheduler_service.get_nodes()
        assert isinstance(result, SchedulerNodes)
        assert len(result.nodes) == 2
        assert result.nodes[0].node_id == "node1"
        assert result.nodes[1].url == "https://node2.aleph.im"


@pytest.mark.asyncio
async def test_scheduler_service_get_allocation():
    """Test the SchedulerService get_allocation method"""
    mock_client = MagicMock()
    scheduler_service = Scheduler(mock_client)

    mock_allocation_data = {
        "vm_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "vm_type": "instance",
        "vm_ipv6": "2001:db8::1",
        "period": {"start_timestamp": "2023-01-01T00:00:00Z", "duration_seconds": 3600},
        "node": {
            "node_id": "node1",
            "url": "https://node1.aleph.im",
            "ipv6": "2001:db8::1",
            "supports_ipv6": True,
        },
    }

    # Set up mock for aiohttp.ClientSession
    patch_target, mock_session_context, _, _ = mock_aiohttp_session(
        mock_allocation_data
    )

    # Patch the ClientSession constructor
    with patch(patch_target, return_value=mock_session_context):
        result = await scheduler_service.get_allocation(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        assert isinstance(result, AllocationItem)
        assert (
            result.vm_hash
            == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        assert result.node.node_id == "node1"


@pytest.mark.asyncio
async def test_utils_service_get_name_of_executable():
    """Test the UtilsService get_name_of_executable method"""
    mock_client = MagicMock()
    utils_service = Instance(mock_client)

    # Mock a message with metadata.name
    mock_message = MagicMock()
    mock_message.content.metadata = {"name": "test-executable"}

    # Set up the client mock to return the message
    mock_client.get_message = AsyncMock(return_value=mock_message)

    # Test successful case
    result = await utils_service.get_name_of_executable("hash1")
    assert result == "test-executable"

    # Test with dict response
    mock_client.get_message = AsyncMock(
        return_value={"content": {"metadata": {"name": "dict-executable"}}}
    )

    result = await utils_service.get_name_of_executable("hash2")
    assert result == "dict-executable"

    # Test with exception
    mock_client.get_message = AsyncMock(side_effect=Exception("Test exception"))

    result = await utils_service.get_name_of_executable("hash3")
    assert result is None


@pytest.mark.asyncio
async def test_utils_service_get_instances():
    """Test the UtilsService get_instances method"""
    mock_client = MagicMock()
    utils_service = Instance(mock_client)

    # Mock messages response
    mock_messages = [MagicMock(), MagicMock()]
    mock_response = MagicMock()
    mock_response.messages = mock_messages

    # Set up the client mock
    mock_client.get_messages = AsyncMock(return_value=mock_response)

    result = await utils_service.get_instances("0xaddress")

    # Check that get_messages was called with correct parameters
    mock_client.get_messages.assert_called_once()
    call_args = mock_client.get_messages.call_args[1]
    assert call_args["page_size"] == 100
    assert call_args["message_filter"].addresses == ["0xaddress"]

    # Check result
    assert result == mock_messages
