import tempfile
from pathlib import Path
from unittest import mock
from unittest.mock import patch

import aiohttp
import pytest
from aioresponses import aioresponses
from aleph_message.models import ItemHash

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client.vm_confidential_client import VmConfidentialClient


@pytest.mark.asyncio
async def test_perform_confidential_operation():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    operation = "confidential/test"

    with aioresponses() as m:
        vm_client = VmConfidentialClient(
            account=account,
            sevctl_path=Path("/"),
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/{operation}",
            status=200,
            payload="mock_response_text",
        )

        response_text = await vm_client.perform_confidential_operation(vm_id, operation)
        assert response_text == '"mock_response_text"'  # ' ' cause by aioresponses
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_confidential_initialize_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    operation = "confidential/initialize"
    node_url = "http://localhost"
    url = f"{node_url}/control/machine/{vm_id}/{operation}"
    headers = {
        "X-SignedPubKey": "test_pubkey_token",
        "X-SignedOperation": "test_operation_token",
    }

    with tempfile.NamedTemporaryFile() as tmp_file:
        tmp_file_bytes = Path(tmp_file.name).read_bytes()
        with aioresponses() as m:
            with patch(
                "aleph.sdk.client.vm_confidential_client.VmConfidentialClient._generate_header",
                return_value=(url, headers),
            ):
                vm_client = VmConfidentialClient(
                    account=account,
                    sevctl_path=Path("/"),
                    node_url=node_url,
                    session=aiohttp.ClientSession(),
                )
                m.post(
                    url,
                    status=200,
                    payload="mock_response_text",
                )
                tmp_file_path = Path(tmp_file.name)
                response_text = await vm_client.initialize(
                    vm_id, session=tmp_file_path, godh=tmp_file_path
                )
                assert (
                    response_text == '"mock_response_text"'
                )  # ' ' cause by aioresponses
                m.assert_called_once_with(
                    url,
                    method="POST",
                    data={
                        "session": tmp_file_bytes,
                        "godh": tmp_file_bytes,
                    },
                    headers=headers,
                )
                await vm_client.session.close()


@pytest.mark.asyncio
async def test_confidential_measurement_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    operation = "confidential/measurement"
    node_url = "http://localhost"
    url = f"{node_url}/control/machine/{vm_id}/{operation}"
    headers = {
        "X-SignedPubKey": "test_pubkey_token",
        "X-SignedOperation": "test_operation_token",
    }

    with aioresponses() as m:
        with patch(
            "aleph.sdk.client.vm_confidential_client.VmConfidentialClient._generate_header",
            return_value=(url, headers),
        ):
            vm_client = VmConfidentialClient(
                account=account,
                sevctl_path=Path("/"),
                node_url=node_url,
                session=aiohttp.ClientSession(),
            )
            m.get(
                url,
                status=200,
                payload=dict(
                    {
                        "sev_info": {
                            "enabled": True,
                            "api_major": 0,
                            "api_minor": 0,
                            "build_id": 0,
                            "policy": 0,
                            "state": "",
                            "handle": 0,
                        },
                        "launch_measure": "test_measure",
                    }
                ),
            )
            measurement = await vm_client.measurement(vm_id)
            assert measurement.launch_measure == "test_measure"
            m.assert_called_once_with(
                url,
                method="GET",
                headers=headers,
            )
            await vm_client.session.close()


@pytest.mark.asyncio
async def test_confidential_inject_secret_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    operation = "confidential/inject_secret"
    node_url = "http://localhost"
    url = f"{node_url}/control/machine/{vm_id}/{operation}"
    headers = {
        "X-SignedPubKey": "test_pubkey_token",
        "X-SignedOperation": "test_operation_token",
    }
    test_secret = "test_secret"
    packet_header = "test_packet_header"

    with aioresponses() as m:
        with patch(
            "aleph.sdk.client.vm_confidential_client.VmConfidentialClient._generate_header",
            return_value=(url, headers),
        ):
            vm_client = VmConfidentialClient(
                account=account,
                sevctl_path=Path("/"),
                node_url=node_url,
                session=aiohttp.ClientSession(),
            )
            m.post(
                url,
                status=200,
                payload="mock_response_text",
            )
            response_text = await vm_client.inject_secret(
                vm_id, secret=test_secret, packet_header=packet_header
            )
            assert response_text == "mock_response_text"
            m.assert_called_once_with(
                url,
                method="POST",
                data={
                    "secret": test_secret,
                    "packet_header": packet_header,
                },
                headers=headers,
            )
            await vm_client.session.close()


@pytest.mark.asyncio
async def test_create_session_command():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    node_url = "http://localhost"
    sevctl_path = Path("/usr/bin/sevctl")
    certificates_path = Path("/")
    policy = 1

    with mock.patch(
        "aleph.sdk.client.vm_confidential_client.run_in_subprocess",
        return_value=True,
    ) as export_mock:
        vm_client = VmConfidentialClient(
            account=account,
            sevctl_path=sevctl_path,
            node_url=node_url,
            session=aiohttp.ClientSession(),
        )
        _ = await vm_client.create_session(vm_id, certificates_path, policy)
        export_mock.assert_called_once_with(
            [
                str(sevctl_path),
                "session",
                "--name",
                str(vm_id),
                str(certificates_path),
                str(policy),
            ],
            check=True,
        )
