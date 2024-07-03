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
            assert response_text == "mock_response_text"
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
            assert response_text == "mock_response_text"
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


@pytest.mark.asyncio
async def test_build_secret_command():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    node_url = "http://localhost"
    sevctl_path = Path("/usr/bin/sevctl")
    current_path = Path().cwd()
    measurement = "test_measurement"
    secret = "test_secret"
    expected_secret_header_path = current_path / "secret_header.bin"
    expected_secret_payload_path = current_path / "secret_payload.bin"

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
        secret_header_path, secret_payload_path = await vm_client.build_secret(
            current_path, current_path, measurement, secret
        )
        assert expected_secret_header_path == secret_header_path
        assert expected_secret_payload_path == secret_payload_path
        export_mock.assert_called_once_with(
            [
                str(sevctl_path),
                "secret",
                "build",
                "--tik",
                str(current_path),
                "--tek",
                str(current_path),
                "--launch-measure-blob",
                measurement,
                "--secret",
                secret,
                str(expected_secret_header_path),
                str(expected_secret_payload_path),
            ],
            check=True,
        )
