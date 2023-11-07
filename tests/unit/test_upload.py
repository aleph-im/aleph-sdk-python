import hashlib
from unittest.mock import AsyncMock, patch

import pytest
from aleph_message.models import StoreMessage
from aleph_message.status import MessageStatus

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.types import StorageEnum


@pytest.fixture
def mock_authenticated_aleph_http_client():
    with patch(
        "aleph.sdk.AuthenticatedAlephHttpClient", autospec=True
    ) as MockHttpClient:
        pkey = get_fallback_private_key()
        account = ETHAccount(private_key=pkey)

        http_session = AsyncMock()
        mock_client = MockHttpClient.return_value
        mock_client.http_session = http_session
        mock_client.account = account
    return mock_client


@pytest.mark.asyncio
async def test_upload_with_message(mock_authenticated_aleph_http_client):
    content = b"Test pyaleph upload\n"
    file_hash = hashlib.sha256(content).hexdigest()

    message = AsyncMock()
    message.content.item_hash = file_hash
    status = MessageStatus.PROCESSED
    mock_authenticated_aleph_http_client.create_store.return_value = (message, status)

    mock_authenticated_aleph_http_client.download_file.return_value = content

    mock_authenticated_aleph_http_client.get_message.return_value = message

    message, status = await mock_authenticated_aleph_http_client.create_store(
        address=mock_authenticated_aleph_http_client.account.get_address(),
        file_content=content,
        storage_engine=StorageEnum.storage,
        sync=True,
    )

    assert status == MessageStatus.PROCESSED
    assert message.content.item_hash == file_hash

    server_content = await mock_authenticated_aleph_http_client.download_file(
        file_hash=file_hash
    )
    assert server_content == content

    server_message = await mock_authenticated_aleph_http_client.get_message(
        item_hash=message.item_hash, message_type=StoreMessage
    )
    assert server_message.content.item_hash == file_hash
