import base64
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
from aleph_message.models.execution.volume import (
    EphemeralVolume,
    ImmutableVolume,
    PersistentVolume,
)

from aleph.sdk.types import SEVInfo
from aleph.sdk.utils import (
    calculate_firmware_hash,
    compute_confidential_measure,
    enum_as_str,
    get_message_type_value,
    parse_volume,
)


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
                "address": "0x1",
                "content": {
                    "Hello": {
                        "vcpus": 1,
                        "memory": 1024,
                        "seconds": 1,
                        "published_ports": None,
                    },
                },
                "key": "test",
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

    assert message.content.model_dump() == content


def test_parse_immutable_volume():
    volume_dict = {
        "ref": "QmX8K1c22WmQBAww5ShWQqwMiFif7XFrJD6iFBj7skQZXW",
        "use_latest": True,
        "comment": "Dummy hash",
    }
    volume = parse_volume(volume_dict)
    volume = parse_volume(volume)
    assert volume
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
    assert isinstance(volume, PersistentVolume)


def test_calculate_firmware_hash(mocker):
    mock_path = mocker.Mock(
        read_bytes=mocker.Mock(return_value=b"abc"),
    )

    assert (
        calculate_firmware_hash(mock_path)
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_compute_confidential_measure():
    """Verify that we properly calculate the measurement we use agains the server

    Validated against the sevctl command:
    $ RUST_LOG=trace sevctl measurement build  --api-major 01 --api-minor 55 --build-id 24 --policy 1
        --tik ~/pycharm-aleph-sdk-python/decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca_tik.bin
        --firmware /usr/share/ovmf/OVMF.fd  --nonce URQNqJAqh/2ep4drjx/XvA

    [2024-07-05T11:19:06Z DEBUG sevctl::measurement] firmware + table len=4194304 sha256: d06471f485c0a61aba5a431ec136b947be56907acf6ed96afb11788ae4525aeb
    [2024-07-05T11:19:06Z DEBUG sevctl::measurement] --tik base64: npOTEc4mtRGfXfB+G6EBdw==
    [2024-07-05T11:19:06Z DEBUG sevctl::measurement] --nonce base64: URQNqJAqh/2ep4drjx/XvA==
    [2024-07-05T11:19:06Z DEBUG sevctl::measurement] Raw measurement: BAE3GAEAAADQZHH0hcCmGrpaQx7BNrlHvlaQes9u2Wr7EXiK5FJa61EUDaiQKof9nqeHa48f17w=
    [2024-07-05T11:19:06Z DEBUG sevctl::measurement] Signed measurement: ls2jv10V3HVShVI/RHCo/a43WO0soLZf0huU9ZZstIw=
    [2024-07-05T11:19:06Z DEBUG sevctl::measurement] Measurement + nonce: ls2jv10V3HVShVI/RHCo/a43WO0soLZf0huU9ZZstIxRFA2okCqH/Z6nh2uPH9e8
    """

    tik = bytes.fromhex("9e939311ce26b5119f5df07e1ba10177")
    assert base64.b64encode(tik) == b"npOTEc4mtRGfXfB+G6EBdw=="
    expected_hash = "d06471f485c0a61aba5a431ec136b947be56907acf6ed96afb11788ae4525aeb"
    nonce = base64.b64decode("URQNqJAqh/2ep4drjx/XvA==")
    sev_info = SEVInfo.model_validate(
        {
            "enabled": True,
            "api_major": 1,
            "api_minor": 55,
            "build_id": 24,
            "policy": 1,
            "state": "running",
            "handle": 1,
        }
    )

    assert (
        base64.b64encode(
            compute_confidential_measure(
                sev_info, tik, expected_hash, nonce=nonce
            ).digest()
        )
        == b"ls2jv10V3HVShVI/RHCo/a43WO0soLZf0huU9ZZstIw="
    )
