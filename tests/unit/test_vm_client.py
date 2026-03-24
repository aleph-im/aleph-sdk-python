import re
from urllib.parse import urlparse

import aiohttp
import pytest
from aiohttp import web
from aioresponses import aioresponses
from aleph_message.models import ItemHash
from yarl import URL

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client.vm_client import VmClient, VmOperation

from .aleph_vm_authentication import (
    SignedOperation,
    SignedPubKeyHeader,
    authenticate_jwk,
    authenticate_websocket_message,
    verify_signed_operation,
)


@pytest.mark.asyncio
async def test_notify_allocation():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post("http://localhost/control/allocation/notify", status=200)
        await vm_client.notify_allocation(vm_id=vm_id)
        assert len(m.requests) == 1
        assert ("POST", URL("http://localhost/control/allocation/notify")) in m.requests
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_perform_operation():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    operation = "reboot"

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/{operation}",
            status=200,
            payload="mock_response_text",
        )

        status, response_text = await vm_client.perform_operation(vm_id, operation)
        assert status == 200
        assert response_text == '"mock_response_text"'  # ' ' cause by aioresponses
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_stop_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/stop",
            status=200,
            payload="mock_response_text",
        )

        status, response_text = await vm_client.stop_instance(vm_id)
        assert status == 200
        assert response_text == '"mock_response_text"'  # ' ' cause by aioresponses
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_reboot_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/reboot",
            status=200,
            payload="mock_response_text",
        )

        status, response_text = await vm_client.reboot_instance(vm_id)
        assert status == 200
        assert response_text == '"mock_response_text"'  # ' ' cause by aioresponses
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_erase_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/erase",
            status=200,
            payload="mock_response_text",
        )

        status, response_text = await vm_client.erase_instance(vm_id)
        assert status == 200
        assert response_text == '"mock_response_text"'  # ' ' cause by aioresponses
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_expire_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/expire",
            status=200,
            payload="mock_response_text",
        )

        status, response_text = await vm_client.expire_instance(vm_id)
        assert status == 200
        assert response_text == '"mock_response_text"'  # ' ' cause by aioresponses
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_get_logs(aiohttp_client):
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    async def websocket_handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                await ws.send_str("mock_log_entry")
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break

        return ws

    app = web.Application()
    app.router.add_route(
        "GET", "/control/machine/{vm_id}/stream_logs", websocket_handler
    )  # Update route to match the URL

    client = await aiohttp_client(app)

    node_url = str(client.make_url("")).rstrip("/")

    vm_client = VmClient(
        account=account,
        node_url=node_url,
        session=client.session,
    )

    logs = []
    async for log in vm_client.get_logs(vm_id):
        logs.append(log)
        if log == "mock_log_entry":
            break

    assert logs == ["mock_log_entry"]
    await vm_client.session.close()


@pytest.mark.asyncio
async def test_authenticate_jwk(aiohttp_client):
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    async def test_authenticate_route(request):
        address = await authenticate_jwk(
            request, domain_name=urlparse(node_url).hostname
        )
        assert vm_client.account.get_address() == address
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route(
        "POST", f"/control/machine/{vm_id}/stop", test_authenticate_route
    )  # Update route to match the URL

    client = await aiohttp_client(app)

    node_url = str(client.make_url("")).rstrip("/")

    vm_client = VmClient(
        account=account,
        node_url=node_url,
        session=client.session,
    )

    status_code, response_text = await vm_client.stop_instance(vm_id)
    assert status_code == 200, response_text
    assert response_text == "ok"

    await vm_client.session.close()


@pytest.mark.asyncio
async def test_websocket_authentication(aiohttp_client):
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    async def websocket_handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        first_message = await ws.receive_json()
        credentials = first_message["auth"]
        sender_address = await authenticate_websocket_message(
            credentials,
            domain_name=urlparse(node_url).hostname,
        )

        assert vm_client.account.get_address() == sender_address
        await ws.send_str(sender_address)

        return ws

    app = web.Application()
    app.router.add_route(
        "GET", "/control/machine/{vm_id}/stream_logs", websocket_handler
    )  # Update route to match the URL

    client = await aiohttp_client(app)

    node_url = str(client.make_url("")).rstrip("/")

    vm_client = VmClient(
        account=account,
        node_url=node_url,
        session=client.session,
    )

    valid = False

    async for address in vm_client.get_logs(vm_id):
        assert address == vm_client.account.get_address()
        valid = True

    # this is done to ensure that the ws as runned at least once and avoid
    # having silent errors
    assert valid

    await vm_client.session.close()


@pytest.mark.asyncio
async def test_vm_client_generate_correct_authentication_headers():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    vm_client = VmClient(
        account=account,
        node_url="http://localhost",
        session=aiohttp.ClientSession(),
    )

    path, headers = await vm_client._generate_header(vm_id, "reboot", method="post")
    signed_pubkey = SignedPubKeyHeader.model_validate_json(headers["X-SignedPubKey"])
    signed_operation = SignedOperation.model_validate_json(headers["X-SignedOperation"])
    address = verify_signed_operation(signed_operation, signed_pubkey)

    assert vm_client.account.get_address() == address


@pytest.mark.asyncio
async def test_reinstall_instance():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            re.compile(rf"http://localhost/control/machine/{vm_id}/reinstall"),
            status=200,
            payload="ok",
        )

        status, response_text = await vm_client.reinstall_instance(vm_id)
        assert status == 200
        assert any("erase_volumes=true" in str(k[1]) for k in m.requests)
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_reinstall_instance_keep_volumes():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            re.compile(rf"http://localhost/control/machine/{vm_id}/reinstall"),
            status=200,
            payload="ok",
        )

        status, _ = await vm_client.reinstall_instance(vm_id, erase_volumes=False)
        assert status == 200
        assert any("erase_volumes=false" in str(k[1]) for k in m.requests)
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_create_backup():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/backup",
            status=200,
            payload="backup_created",
        )

        status, response_text = await vm_client.create_backup(vm_id)
        assert status == 200
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_create_backup_with_options():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            re.compile(rf"http://localhost/control/machine/{vm_id}/backup"),
            status=200,
            payload="backup_created",
        )

        status, _ = await vm_client.create_backup(
            vm_id, include_volumes=True, skip_fsfreeze=True
        )
        assert status == 200
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_get_backup():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.get(
            f"http://localhost/control/machine/{vm_id}/backup",
            status=200,
            payload={"backups": []},
        )

        status, response_text = await vm_client.get_backup(vm_id)
        assert status == 200
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_delete_backup():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    backup_id = "abc123"

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.delete(
            f"http://localhost/control/machine/{vm_id}/backup/{backup_id}",
            status=200,
            payload="deleted",
        )

        status, response_text = await vm_client.delete_backup(vm_id, backup_id)
        assert status == 200
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_delete_backup_invalid_id():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    vm_client = VmClient(
        account=account,
        node_url="http://localhost",
        session=aiohttp.ClientSession(),
    )

    with pytest.raises(ValueError, match="Invalid backup_id"):
        await vm_client.delete_backup(vm_id, "../etc/passwd")

    with pytest.raises(ValueError, match="Invalid backup_id"):
        await vm_client.delete_backup(vm_id, "id/with/slashes")

    await vm_client.session.close()


@pytest.mark.asyncio
async def test_get_restore_endpoint():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    vm_client = VmClient(
        account=account,
        node_url="http://localhost",
        session=aiohttp.ClientSession(),
    )

    url, headers = await vm_client.get_restore_endpoint(vm_id)
    assert f"/control/machine/{vm_id}/restore" in url
    assert "X-SignedPubKey" in headers
    assert "X-SignedOperation" in headers
    await vm_client.session.close()


@pytest.mark.asyncio
async def test_restore_from_volume():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/restore",
            status=200,
            payload="restored",
        )

        status, response_text = await vm_client.restore_from_volume(
            vm_id, "volume_hash_abc123"
        )
        assert status == 200
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_restore_from_file(tmp_path):
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    rootfs = tmp_path / "rootfs.img"
    rootfs.write_bytes(b"fake rootfs content")

    with aioresponses() as m:
        vm_client = VmClient(
            account=account,
            node_url="http://localhost",
            session=aiohttp.ClientSession(),
        )
        m.post(
            f"http://localhost/control/machine/{vm_id}/restore",
            status=200,
            payload="restored",
        )

        status, response_text = await vm_client.restore_from_file(vm_id, rootfs)
        assert status == 200
        await vm_client.session.close()


@pytest.mark.asyncio
async def test_restore_from_file_not_found():
    account = ETHAccount(private_key=b"0x" + b"1" * 30)
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    vm_client = VmClient(
        account=account,
        node_url="http://localhost",
        session=aiohttp.ClientSession(),
    )

    status, error_text = await vm_client.restore_from_file(
        vm_id, "/nonexistent/rootfs.img"
    )
    assert status is None
    assert "No such file or directory" in error_text
    await vm_client.session.close()


def test_vm_operation_enum_values():
    assert VmOperation.STOP == "stop"
    assert VmOperation.REBOOT == "reboot"
    assert VmOperation.ERASE == "erase"
    assert VmOperation.BACKUP == "backup"
    assert VmOperation.RESTORE == "restore"
    assert VmOperation.REINSTALL == "reinstall"
    assert VmOperation.EXPIRE == "expire"
    assert VmOperation.STREAM_LOGS == "stream_logs"
