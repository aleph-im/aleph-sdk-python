import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest as pytest
from aleph_message.models import (
    AggregateMessage,
    AlephMessage,
    ForgetMessage,
    MessageType,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.status import MessageStatus

from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.conf import settings
from aleph.sdk.models.post import PostFilter
from aleph.sdk.node import DomainNode
from aleph.sdk.types import Account, StorageEnum


class MockPostResponse:
    def __init__(self, response_message: Any, sync: bool):
        self.response_message = response_message
        self.sync = sync

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        ...

    @property
    def status(self):
        return 200 if self.sync else 202

    def raise_for_status(self):
        if self.status not in [200, 202]:
            raise Exception("Bad status code")

    async def json(self):
        message_status = "processed" if self.sync else "pending"
        return {
            "message_status": message_status,
            "publication_status": {"status": "success", "failed": []},
            "hash": "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy",
            "message": self.response_message,
        }

    async def text(self):
        return json.dumps(await self.json())


class MockGetResponse:
    def __init__(self, response_message: Callable[[int], Dict[str, Any]], page=1):
        self.response_message = response_message
        self.page = page

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        ...

    @property
    def status(self):
        return 200

    def raise_for_status(self):
        if self.status != 200:
            raise Exception("Bad status code")

    async def json(self):
        return self.response_message(self.page)


class MockWsConnection:
    def __init__(self, messages: List[AlephMessage]):
        self.messages = messages
        self.i = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        ...

    def __aiter__(self):
        return self

    def __anext__(self):
        try:
            message = self.messages[self.i]
            self.i += 1
            return message
        except IndexError:
            raise StopAsyncIteration


@pytest.fixture
def mock_session_with_two_messages(
    ethereum_account: Account, raw_messages_response: Callable[[int], Dict[str, Any]]
) -> AuthenticatedAlephClient:
    http_session = AsyncMock()
    http_session.post = MagicMock()
    http_session.post.side_effect = lambda *args, **kwargs: MockPostResponse(
        response_message={
            "type": "post",
            "channel": "TEST",
            "content": {"Hello": "World"},
            "key": "QmBlahBlahBlah",
            "item_hash": "QmBlahBlahBlah",
        },
        sync=kwargs.get("sync", False),
    )
    http_session.get = MagicMock()
    http_session.get.side_effect = lambda *args, **kwargs: MockGetResponse(
        response_message=raw_messages_response,
        page=kwargs.get("params", {}).get("page", 1),
    )
    http_session.ws_connect = MagicMock()
    http_session.ws_connect.side_effect = lambda *args, **kwargs: MockWsConnection(
        messages=raw_messages_response(1)["messages"]
    )

    client = AuthenticatedAlephClient(
        account=ethereum_account, api_server="http://localhost"
    )
    client.http_session = http_session

    return client


def test_node_init(mock_session_with_two_messages, aleph_messages):
    node = DomainNode(
        session=mock_session_with_two_messages,
    )
    assert mock_session_with_two_messages.http_session.get.called_once
    assert mock_session_with_two_messages.http_session.ws_connect.called_once
    assert node.session == mock_session_with_two_messages
    assert len(node) >= 2


@pytest.fixture
def mock_node_with_post_success(mock_session_with_two_messages) -> DomainNode:
    node = DomainNode(session=mock_session_with_two_messages)
    return node


@pytest.mark.asyncio
async def test_create_post(mock_node_with_post_success):
    async with mock_node_with_post_success as session:
        content = {"Hello": "World"}

        post_message, message_status = await session.create_post(
            post_content=content,
            post_type="TEST",
            channel="TEST",
            sync=False,
        )

    assert mock_node_with_post_success.session.http_session.post.called_once
    assert isinstance(post_message, PostMessage)
    assert message_status == MessageStatus.PENDING


@pytest.mark.asyncio
async def test_create_aggregate(mock_node_with_post_success):
    async with mock_node_with_post_success as session:
        aggregate_message, message_status = await session.create_aggregate(
            key="hello",
            content={"Hello": "world"},
            channel="TEST",
        )

    assert mock_node_with_post_success.session.http_session.post.called_once
    assert isinstance(aggregate_message, AggregateMessage)


@pytest.mark.asyncio
async def test_create_store(mock_node_with_post_success):
    mock_ipfs_push_file = AsyncMock()
    mock_ipfs_push_file.return_value = "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"

    mock_node_with_post_success.ipfs_push_file = mock_ipfs_push_file

    async with mock_node_with_post_success as node:
        _ = await node.create_store(
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

        _ = await node.create_store(
            file_hash="QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

    mock_storage_push_file = AsyncMock()
    mock_storage_push_file.return_value = (
        "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"
    )
    mock_node_with_post_success.storage_push_file = mock_storage_push_file
    async with mock_node_with_post_success as node:
        store_message, message_status = await node.create_store(
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.storage,
        )

    assert mock_node_with_post_success.session.http_session.post.called
    assert isinstance(store_message, StoreMessage)


@pytest.mark.asyncio
async def test_create_program(mock_node_with_post_success):
    async with mock_node_with_post_success as node:
        program_message, message_status = await node.create_program(
            program_ref="cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
            entrypoint="main:app",
            runtime="facefacefacefacefacefacefacefacefacefacefacefacefacefacefaceface",
            channel="TEST",
            metadata={"tags": ["test"]},
        )

    assert mock_node_with_post_success.session.http_session.post.called_once
    assert isinstance(program_message, ProgramMessage)


@pytest.mark.asyncio
async def test_forget(mock_node_with_post_success):
    async with mock_node_with_post_success as node:
        forget_message, message_status = await node.forget(
            hashes=["QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"],
            reason="GDPR",
            channel="TEST",
        )

    assert mock_node_with_post_success.session.http_session.post.called_once
    assert isinstance(forget_message, ForgetMessage)


@pytest.mark.asyncio
async def test_download_file(mock_node_with_post_success):
    mock_node_with_post_success.session.download_file = AsyncMock()
    mock_node_with_post_success.session.download_file.return_value = b"HELLO"

    # remove file locally
    if os.path.exists(settings.CACHE_FILES_PATH / Path("QmAndSoOn")):
        os.remove(settings.CACHE_FILES_PATH / Path("QmAndSoOn"))

    # fetch from mocked response
    async with mock_node_with_post_success as node:
        file_content = await node.download_file(
            file_hash="QmAndSoOn",
        )

    assert mock_node_with_post_success.session.http_session.get.called_once
    assert file_content == b"HELLO"

    # fetch cached
    async with mock_node_with_post_success as node:
        file_content = await node.download_file(
            file_hash="QmAndSoOn",
        )

    assert file_content == b"HELLO"


@pytest.mark.asyncio
async def test_submit_message(mock_node_with_post_success):
    content = {"Hello": "World"}
    async with mock_node_with_post_success as node:
        message, status = await node.submit(
            content={
                "address": "0x1234567890123456789012345678901234567890",
                "time": 1234567890,
                "type": "TEST",
                "content": content,
            },
            message_type=MessageType.post,
        )

    assert mock_node_with_post_success.session.http_session.post.called_once
    assert message.content.content == content
    assert status == MessageStatus.PENDING


@pytest.mark.asyncio
async def test_amend_post(mock_node_with_post_success):
    async with mock_node_with_post_success as node:
        post_message, status = await node.create_post(
            post_content={
                "Hello": "World",
            },
            post_type="to-be-amended",
            channel="TEST",
        )

    assert mock_node_with_post_success.session.http_session.post.called_once
    assert post_message.content.content == {"Hello": "World"}
    assert status == MessageStatus.PENDING

    async with mock_node_with_post_success as node:
        amend_message, status = await node.create_post(
            post_content={
                "Hello": "World",
                "Foo": "Bar",
            },
            post_type="amend",
            ref=post_message.item_hash,
            channel="TEST",
        )

    async with mock_node_with_post_success as node:
        posts = (
            await node.get_posts(
                post_filter=PostFilter(
                    hashes=[post_message.item_hash],
                )
            )
        ).posts
    assert posts[0].content == {"Hello": "World", "Foo": "Bar"}
