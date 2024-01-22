import datetime

import pytest as pytest
from aleph_message.models import (
    AggregateMessage,
    Chain,
    ForgetMessage,
    ItemType,
    MessageType,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.models.execution.environment import MachineResources
from aleph_message.models.execution.volume import (
    EphemeralVolume,
    ImmutableVolume,
    MachineVolume,
    PersistentVolume,
)

from aleph.sdk.utils import enum_as_str, get_message_type_value, parse_volume


def test_get_message_type_value():
    assert get_message_type_value(PostMessage) == MessageType.post
    assert get_message_type_value(AggregateMessage) == MessageType.aggregate
    assert get_message_type_value(StoreMessage) == MessageType.store
    assert get_message_type_value(ProgramMessage) == MessageType.program
    assert get_message_type_value(ForgetMessage) == MessageType.forget


def test_enum_as_str():
    assert enum_as_str("simple string") == "simple string"
    assert enum_as_str(Chain("ETH")) == "ETH"
    assert enum_as_str(Chain.ETH) == "ETH"
    assert enum_as_str(ItemType("inline")) == "inline"
    assert enum_as_str(ItemType.inline) == "inline"


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
                "content": {"Hello": datetime.timedelta()},
                "key": "test",
                "address": "0x1",
                "time": 1.0,
            },
        ),
        (
            MessageType.aggregate,
            {
                "content": {"Hello": datetime.datetime.now().astimezone()},
                "key": "test",
                "address": "0x1",
                "time": 1.0,
            },
        ),
        (
            MessageType.aggregate,
            {
                "content": {"Hello": datetime.datetime.now().astimezone().isoformat()},
                "key": "test",
                "address": "0x1",
                "time": 1.0,
            },
        ),
        (
            MessageType.aggregate,
            {
                "content": {"Hello": datetime.datetime.now().astimezone().timestamp()},
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
        message = await session._prepare_aleph_message(
            message_type=message_type,
            content=content,
            channel="TEST",
        )

    assert message.content.dict() == content


def test_parse_immutable_volume():
    volume_dict = {
        "ref": "QmX8K1c22WmQBAww5ShWQqwMiFif7XFrJD6iFBj7skQZXW",
        "use_latest": True,
        "comment": "Dummy hash",
    }
    volume = parse_volume(volume_dict)
    volume = parse_volume(volume)
    assert volume
    assert isinstance(volume, MachineVolume)
    assert isinstance(volume, ImmutableVolume)


def test_parse_ephemeral_volume():
    volume_dict = {
        "comment": "Dummy hash",
        "ephemeral": True,
        "size_mib": 1,
    }
    volume = parse_volume(volume_dict)
    volume = parse_volume(volume)
    assert volume
    assert isinstance(volume, MachineVolume)
    assert isinstance(volume, EphemeralVolume)


def test_parse_persistent_volume():
    volume_dict = {
        "parent": {
            "ref": "QmX8K1c22WmQBAww5ShWQqwMiFif7XFrJD6iFBj7skQZXW",
            "use_latest": True,
            "comment": "Dummy hash",
        },
        "persistence": "host",
        "name": "test",
        "size_mib": 1,
    }
    volume = parse_volume(volume_dict)
    volume = parse_volume(volume)
    assert volume
    assert isinstance(volume, MachineVolume)
    assert isinstance(volume, PersistentVolume)
