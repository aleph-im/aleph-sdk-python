import pytest
from aleph.sdk import AlephClient
from aleph.sdk.conf import settings as sdk_settings


@pytest.mark.asyncio
def test_download():
    with AlephClient(
        api_server=sdk_settings.API_HOST
    ) as client:
        file_size: int = 0
        try:
            file_content = client.download_file("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH")  # File is 5B
            file_size = len(file_content)
        except Exception as e:
            pass
        assert file_size == 5


@pytest.mark.asyncio
def test_download_ipfs():
    with AlephClient(
            api_server=sdk_settings.API_HOST
    ) as client:
        file_size: int = 0
        try:
            file_content = client.download_file_ipfs(
                "Qmdy5LaAL4eghxE7JD6Ah5o4PJGarjAV9st8az2k52i1vq")  ## 5817703 B FILE
            file_size = len(file_content)
        except Exception as e:
            pass
        assert file_size == 5817703
