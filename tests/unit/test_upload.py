import hashlib

import pytest
from aleph_message.models import StoreMessage
from aleph_message.status import MessageStatus

from src.aleph.sdk.chains.common import get_fallback_private_key
from src.aleph.sdk.chains.ethereum import ETHAccount
from src.aleph.sdk.client import AuthenticatedAlephHttpClient
from src.aleph.sdk.types import StorageEnum


@pytest.mark.asyncio
async def test_upload_with_message():
    pkey = get_fallback_private_key()
    account = ETHAccount(private_key=pkey)

    content = b"Test pyaleph upload\n"
    file_hash = hashlib.sha256(content).hexdigest()
    async with AuthenticatedAlephHttpClient(account=account, api_server=None) as client:
        message, status = await client.create_store(
            address=account.get_address(),
            file_content=content,
            storage_engine=StorageEnum.storage,
            sync=True,
        )
        print(message, status)

        assert status == MessageStatus.PROCESSED
        assert message.content.item_hash == file_hash

        server_content = await client.download_file(file_hash=file_hash)
        assert server_content == content

        server_message = await client.get_message(
            item_hash=message.item_hash, message_type=StoreMessage
        )
        assert server_message.content.item_hash == file_hash
