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

from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.node import DomainNode
from aleph.sdk.types import Account, StorageEnum


@pytest.fixture
def mock_node_with_post_success(
    ethereum_account: Account,
) -> DomainNode:
    class MockPostResponse:
        def __init__(self, sync: bool):
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
                "message": {
                    "type": "post",
                    "channel": "TEST",
                    "content": {"Hello": "World"},
                    "key": "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy",
                    "item_hash": "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy",
                },
            }

        async def text(self):
            return json.dumps(await self.json())

    class MockGetResponse:
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
            return {
                "messages": [
                    {
                        "item_hash": "<item_hash_1>",
                        "type": "AGGREGATE",
                        "chain": "ETH",
                        "sender": "<sender_address_1>",
                        "signature": "<signature_1>",
                        "item_type": "inline",
                        "item_content": "<item_content_1>",
                        "content": {
                            "key": "<key_1>",
                            "time": 1692026263.662,
                            "address": "<address_1>",
                            "content": {
                                "1692026263168": {
                                    "nonce": "<nonce_1>",
                                    "sha256": "<sha256_1>",
                                    "version": "x25519-xsalsa20-poly1305",
                                    "ciphertext": "<ciphertext_1>",
                                    "ephemPublicKey": "<ephemPublicKey_1>",
                                }
                            },
                        },
                        "time": 1692026263.662,
                        "channel": "UNSLASHED",
                        "size": 734,
                        "confirmations": [],
                        "confirmed": False,
                    },
                    {
                        "item_hash": "<item_hash_2>",
                        "type": "POST",
                        "chain": "ETH",
                        "sender": "<sender_address_2>",
                        "signature": "<signature_2>",
                        "item_type": "storage",
                        "item_content": None,
                        "content": {
                            "time": 1692026021.1257718,
                            "type": "aleph-network-metrics",
                            "address": "<address_2>",
                            "content": {
                                "tags": ["mainnet"],
                                "metrics": {
                                    "ccn": [
                                        {
                                            "asn": 24940,
                                            "url": "<url_2>",
                                            "as_name": "<as_name_2>",
                                            "node_id": "<node_id_2>",
                                            "version": "<version_2>",
                                            "txs_total": 0,
                                            "measured_at": 1692025827.943929,
                                            "base_latency": 0.1020817756652832,
                                            "metrics_latency": 0.28051209449768066,
                                            "pending_messages": 0,
                                            "aggregate_latency": 0.06148695945739746,
                                            "base_latency_ipv4": 0.1020817756652832,
                                            "eth_height_remaining": 276,
                                            "file_download_latency": 0.10703206062316895,
                                        }
                                    ],
                                    "server": "151.115.63.76",
                                    "server_asn": 12876,
                                    "server_as_name": "Online SAS, FR",
                                },
                                "version": "1.0",
                            },
                        },
                        "time": 1692026021.132849,
                        "channel": "aleph-scoring",
                        "size": 122537,
                        "confirmations": [],
                        "confirmed": False,
                    },
                ],
                "pagination_item": "messages",
                "pagination_page": 1,
                "pagination_per_page": 20,
                "pagination_total": 1,
            }

    http_session = AsyncMock()
    http_session.post = MagicMock()
    http_session.post.side_effect = lambda *args, **kwargs: MockPostResponse(
        sync=kwargs.get("sync", False)
    )
    http_session.get = MagicMock()
    http_session.get.return_value = MockGetResponse()

    client = AuthenticatedAlephClient(
        account=ethereum_account, api_server="http://localhost"
    )
    client.http_session = http_session

    node = DomainNode(session=client)
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

    async with mock_node_with_post_success as session:
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
    mock_node_with_post_success.storage_push_file = mock_storage_push_file
    async with mock_node_with_post_success as session:
        store_message, message_status = await session.create_store(
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.storage,
        )

    assert mock_node_with_post_success.session.http_session.post.called
    assert isinstance(store_message, StoreMessage)


@pytest.mark.asyncio
async def test_create_program(mock_node_with_post_success):
    async with mock_node_with_post_success as session:
        program_message, message_status = await session.create_program(
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
    async with mock_node_with_post_success as session:
        forget_message, message_status = await session.forget(
            hashes=["QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"],
            reason="GDPR",
            channel="TEST",
        )

    assert mock_node_with_post_success.session.http_session.post.called_once
    assert isinstance(forget_message, ForgetMessage)
