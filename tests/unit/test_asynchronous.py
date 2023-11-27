import datetime
from unittest.mock import AsyncMock

import pytest as pytest
from aleph_message.models import (
    AggregateMessage,
    ForgetMessage,
    InstanceMessage,
    MessageType,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.models.execution.environment import MachineResources
from aleph_message.status import MessageStatus

from aleph.sdk.types import StorageEnum


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
async def test_create_instance(mock_session_with_post_success):
    async with mock_session_with_post_success as session:
        instance_message, message_status = await session.create_instance(
            rootfs="cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
            rootfs_size=1,
            rootfs_name="rootfs",
            channel="TEST",
            metadata={"tags": ["test"]},
        )

    assert mock_session_with_post_success.http_session.post.called_once
    assert isinstance(instance_message, InstanceMessage)


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message_type, content",
    [
        (
            MessageType.aggregate,
            {
                "content": {"Hello": datetime.datetime.now()},
                "key": "test",
                "address": "0x1",
                "time": 1.0,
            },
        ),
        (
            MessageType.aggregate,
            {
                "content": {"Hello": datetime.date.today()},
                "key": "test",
                "address": "0x1",
                "time": 1.0,
            },
        ),
        (
            MessageType.aggregate,
            {
                "content": {"Hello": datetime.time()},
                "key": "test",
                "address": "0x1",
                "time": 1.0,
            },
        ),
        (
            MessageType.aggregate,
            {
                "content": {
                    "Hello": MachineResources(
                        vcpus=1,
                        memory=1024,
                        seconds=1,
                    )
                },
                "key": "test",
                "address": "0x1",
                "time": 1.0,
            },
        ),
    ],
)
async def test_prepare_aleph_message(
    mock_session_with_post_success, message_type, content
):
    # Call the function under test
    async with mock_session_with_post_success as session:
        await session._prepare_aleph_message(
            message_type=message_type,
            content=content,
            channel="TEST",
        )
