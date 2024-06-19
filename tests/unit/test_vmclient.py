import aiohttp
import pytest
from aiohttp import web
from aioresponses import aioresponses
from aleph_message.models import ItemHash

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client.vmclient import VmClient


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
        assert m.requests
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
    app.router.add_route("GET", "/logs/{vm_id}", websocket_handler)

    client = await aiohttp_client(app)

    vm_client = VmClient(
        account=account,
        node_url=str(client.make_url("/")).rstrip("/"),
        session=client.session,
    )

    logs = []
    async for log in vm_client.get_logs(vm_id):
        logs.append(log)
        if log == "mock_log_entry":
            break

    assert logs == ["mock_log_entry"]
    await vm_client.session.close()
