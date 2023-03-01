import json
from unittest.mock import AsyncMock, MagicMock

import pytest as pytest
from aleph_message.models import (
    AggregateMessage,
    ForgetMessage,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.status import MessageStatus

from aleph.sdk.client import AuthenticatedAlephClient
from aleph.sdk.types import Account, StorageEnum


@pytest.fixture
def mock_session_with_post_success(
    ethereum_account: Account,
) -> AuthenticatedAlephClient:
    class MockResponse:
        def __init__(self, sync: bool):
            self.sync = sync

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            ...

        @property
        def status(self):
            return 200 if self.sync else 202

        async def json(self):
            message_status = "processed" if self.sync else "pending"
            return {
                "message_status": message_status,
                "publication_status": {"status": "success", "failed": []},
            }

        async def text(self):
            return json.dumps(await self.json())

    http_session = AsyncMock()
    http_session.post = MagicMock()
    http_session.post.side_effect = lambda *args, **kwargs: MockResponse(
        sync=kwargs.get("sync", False)
    )

    client = AuthenticatedAlephClient(
        account=ethereum_account, api_server="http://localhost"
    )
    client.http_session = http_session

    return client


@pytest.mark.asyncio
async def test_create_post(mock_session_with_post_success):
    async with mock_session_with_post_success as session:
        content = {"Hello": "World"}

        post_message, message_status = await session.create_post(
            post_content=content,
            post_type="TEST",
            channel="TEST",
            sync=False,
        )

    assert mock_session_with_post_success.http_session.post.called_once
    assert isinstance(post_message, PostMessage)
    assert message_status == MessageStatus.PENDING


@pytest.mark.asyncio
async def test_create_aggregate(mock_session_with_post_success):
    async with mock_session_with_post_success as session:
        aggregate_message, message_status = await session.create_aggregate(
            key="hello",
            content={"Hello": "world"},
            channel="TEST",
        )

    assert mock_session_with_post_success.http_session.post.called_once
    assert isinstance(aggregate_message, AggregateMessage)


@pytest.mark.asyncio
async def test_create_store(mock_session_with_post_success):
    mock_ipfs_push_file = AsyncMock()
    mock_ipfs_push_file.return_value = "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"

    mock_session_with_post_success.ipfs_push_file = mock_ipfs_push_file

    async with mock_session_with_post_success as session:
        _ = await session.create_store(
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

        _ = await session.create_store(
            file_hash="QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

    mock_storage_push_file = AsyncMock()
    mock_storage_push_file.return_value = (
        "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"
    )
    mock_session_with_post_success.storage_push_file = mock_storage_push_file
    async with mock_session_with_post_success as session:
        store_message, message_status = await session.create_store(
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.storage,
        )

    assert mock_session_with_post_success.http_session.post.called
    assert isinstance(store_message, StoreMessage)


@pytest.mark.asyncio
async def test_create_program(mock_session_with_post_success):
    async with mock_session_with_post_success as session:
        program_message, message_status = await session.create_program(
            program_ref="cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
            entrypoint="main:app",
            runtime="facefacefacefacefacefacefacefacefacefacefacefacefacefacefaceface",
            channel="TEST",
            metadata={"tags": ["test"]},
        )

    assert mock_session_with_post_success.http_session.post.called_once
    assert isinstance(program_message, ProgramMessage)


@pytest.mark.asyncio
async def test_forget(mock_session_with_post_success):
    async with mock_session_with_post_success as session:
        forget_message, message_status = await session.forget(
            hashes=["QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"],
            reason="GDPR",
            channel="TEST",
        )

    assert mock_session_with_post_success.http_session.post.called_once
    assert isinstance(forget_message, ForgetMessage)
