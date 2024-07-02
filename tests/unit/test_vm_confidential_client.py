import tempfile
from pathlib import Path
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

        status, response_text = await vm_client.perform_confidential_operation(
            vm_id, operation
        )
        assert status == 200
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
                status, response_text = await vm_client.initialize(
                    vm_id, session=tmp_file_path, godh=tmp_file_path
                )
                assert status == 200
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
            m.post(
                url,
                status=200,
                payload="mock_response_text",
            )
            status, response_text = await vm_client.measurement(vm_id)
            assert status == 200
            assert response_text == 'mock_response_text'  # ' ' cause by aioresponses
            m.assert_called_once_with(
                url,
                method="POST",
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
    packed_header = "test_packed_header"

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
            status, response_text = await vm_client.inject_secret(
                vm_id, secret=test_secret, packed_header=packed_header
            )
            assert status == 200
            assert response_text == 'mock_response_text'  # ' ' cause by aioresponses
            m.assert_called_once_with(
                url,
                method="POST",
                data={
                    "secret": test_secret,
                    "packed_header": packed_header,
                },
                headers=headers,
            )
            await vm_client.session.close()
