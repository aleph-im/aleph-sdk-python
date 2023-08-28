import hashlib
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
import pytest

from aleph.sdk import AlephClient
from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from examples.store import do_upload_with_message


@pytest.mark.asyncio
async def test_upload_with_message():
    pkey = get_fallback_private_key()
    account = ETHAccount(private_key=pkey)

    content = "Test Py Aleph upload\n"
    content_bytes = content.encode("utf-8")

    with NamedTemporaryFile(mode="w", delete=False) as temp_file:
        temp_file.write(content)

    file_name = Path(temp_file.name)
    actual_item_hash = hashlib.sha256(
        content.encode()
    ).hexdigest()  # Calculate the hash of the content

    test = await do_upload_with_message(
        account=account,
        engine="STORAGE",
        channel="Test",
        filename=file_name,
        item_hash=actual_item_hash,
    )
    async with AlephClient(api_server="http://0.0.0.0:4024") as client:
        file_content = await client.download_file(test["hash"])
        assert file_content == content_bytes
