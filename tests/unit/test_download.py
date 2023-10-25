from io import BytesIO

import pytest

from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.client import LightNode
from aleph.sdk.conf import settings as sdk_settings


@pytest.mark.parametrize(
    "file_hash,expected_size",
    [
        ("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH", 5),
        ("Qmdy5LaAL4eghxE7JD6Ah5o4PJGarjAV9st8az2k52i1vq", 5817703),
    ],
)
@pytest.mark.asyncio
async def test_download(file_hash: str, expected_size: int):
    async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:
        file_content = await client.download_file(file_hash)  # File is 5B
        file_size = len(file_content)
        assert file_size == expected_size


@pytest.mark.asyncio
async def test_download_light_node(solana_account):
    session = AuthenticatedAlephHttpClient(
        solana_account, api_server=sdk_settings.API_HOST
    )
    async with LightNode(session=session) as node:
        file_content = await node.download_file(
            "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
        )
        file_size = len(file_content)
        assert file_size == 5


@pytest.mark.parametrize(
    "file_hash,expected_size",
    [
        ("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH", 5),
        ("Qmdy5LaAL4eghxE7JD6Ah5o4PJGarjAV9st8az2k52i1vq", 5817703),
    ],
)
@pytest.mark.asyncio
async def test_download_ipfs(file_hash: str, expected_size: int):
    async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:
        file_content = await client.download_file_ipfs(file_hash)  # 5817703 B FILE
        file_size = len(file_content)
        assert file_size == expected_size


@pytest.mark.asyncio
async def test_download_to_buffer_light_node(solana_account):
    session = AuthenticatedAlephHttpClient(
        solana_account, api_server=sdk_settings.API_HOST
    )
    async with LightNode(session=session) as node:
        item_hash = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
        del node[item_hash]
        buffer = BytesIO()
        await node.download_file_to_buffer(
            "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH",
            buffer,
        )
        file_size = buffer.getbuffer().nbytes
        assert file_size == 5
