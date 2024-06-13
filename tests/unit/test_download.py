import tempfile
from pathlib import Path

import pytest

from aleph.sdk import AlephHttpClient

from .conftest import make_mock_get_session


def make_mock_download_client(item_hash: str) -> AlephHttpClient:
    if item_hash == "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH":
        return make_mock_get_session(b"test\n")
    if item_hash == "Qmdy5LaAL4eghxE7JD6Ah5o4PJGarjAV9st8az2k52i1vq":
        return make_mock_get_session(bytes(5817703))
    raise NotImplementedError


@pytest.mark.parametrize(
    "file_hash,expected_size",
    [
        ("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH", 5),
        ("Qmdy5LaAL4eghxE7JD6Ah5o4PJGarjAV9st8az2k52i1vq", 5817703),
    ],
)
@pytest.mark.asyncio
async def test_download(file_hash: str, expected_size: int):
    mock_download_client = make_mock_download_client(file_hash)
    async with mock_download_client:
        file_content = await mock_download_client.download_file(file_hash)
    file_size = len(file_content)
    assert file_size == expected_size


@pytest.mark.asyncio
async def test_download_to_file():
    file_hash = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    mock_download_client = make_mock_download_client(file_hash)
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        download_path = temp_dir_path / "test.txt"

        async with mock_download_client:
            returned_path = await mock_download_client.download_file_to_path(
                file_hash, str(download_path)
            )

        assert returned_path == download_path
        assert download_path.is_file()
        with open(download_path, "r") as file:
            assert file.read().strip() == "test"


@pytest.mark.parametrize(
    "file_hash,expected_size",
    [
        ("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH", 5),
        ("Qmdy5LaAL4eghxE7JD6Ah5o4PJGarjAV9st8az2k52i1vq", 5817703),
    ],
)
@pytest.mark.asyncio
async def test_download_ipfs(file_hash: str, expected_size: int):
    mock_download_client = make_mock_download_client(file_hash)
    async with mock_download_client:
        file_content = await mock_download_client.download_file_ipfs(file_hash)
    file_size = len(file_content)
    assert file_size == expected_size
