import hashlib

import pytest
from aleph_message.status import MessageStatus

from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.types import StorageEnum


@pytest.mark.asyncio
async def test_upload_with_message():
    pkey = get_fallback_private_key()
    account = ETHAccount(private_key=pkey)

    content = b"Test pyaleph upload\n"
    file_hash = hashlib.sha256(content).hexdigest()

    async with AuthenticatedAlephClient(
        account=account, api_server="http://0.0.0.0:8000"
    ) as client:
        message, status = await client.create_store(
            address=account.get_address(),
            file_content=content,
            storage_engine=StorageEnum.storage,
            sync=True,
        )

    assert status == MessageStatus.PROCESSED
    assert message.content.item_hash == file_hash

    server_content = await client.download_file(file_hash=file_hash)
    assert server_content == content
