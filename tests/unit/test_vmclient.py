import aiohttp
import pytest
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
