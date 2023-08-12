import pytest

from aleph.sdk import AlephClient
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
    async with AlephClient(api_server=sdk_settings.API_HOST) as client:
        file_content = await client.download_file(file_hash)  # File is 5B
        file_size = len(file_content)
        assert file_size == expected_size


@pytest.mark.parametrize(
    "file_hash,expected_size",
    [
        ("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH", 5),
        ("Qmdy5LaAL4eghxE7JD6Ah5o4PJGarjAV9st8az2k52i1vq", 5817703),
    ],
)
@pytest.mark.asyncio
async def test_download_ipfs(file_hash: str, expected_size: int):
    async with AlephClient(api_server=sdk_settings.API_HOST) as client:
        file_content = await client.download_file_ipfs(file_hash)  # 5817703 B FILE
        file_size = len(file_content)
        assert file_size == expected_size
