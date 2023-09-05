import asyncio
import base64

import pytest
from fastapi.testclient import TestClient

from tests.unit.test_app.main import app

# Note: for some reason, the test client must be declared at the same level as the import.
client = TestClient(app)


@pytest.mark.asyncio
async def test_app_event():
    # Call the app with an ASGI context
    scope = {
        "type": "aleph.message",
    }

    async def receive():
        return {"type": "aleph.message", "body": b"BODY", "more_body": False}

    send_queue: asyncio.Queue = asyncio.Queue()

    async def send(dico):
        await send_queue.put(dico)

    await app(scope, receive, send)


def test_app_http():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"index": "/"}


def test_get_vm_hash(mocker):
    vm_hash = "deadbeef" * 8
    # Uses the same logic as
    # https://github.com/aleph-im/aleph-vm/blob/main/runtimes/aleph-debian-11-python/init1.py#L488
    item_hash_binary: bytes = base64.b16decode(vm_hash.encode().upper())
    hostname = base64.b32encode(item_hash_binary).decode().strip("=").lower()

    mocker.patch("socket.gethostname", return_value=hostname)

    assert app.vm_hash == vm_hash


def test_get_vm_hash_no_vm(mocker):
    mocker.patch("socket.gethostname", return_value="not-a-vm")

    assert app.vm_hash is None
