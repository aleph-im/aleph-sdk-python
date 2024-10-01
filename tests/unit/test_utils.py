import base64
import datetime

import base58
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
    PersistentVolume,
)

from aleph.sdk.account import detect_chain_from_private_key, is_valid_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.chains.solana import SOLAccount, parse_solana_private_key
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
    sev_info = SEVInfo.parse_obj(
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


def test_parse_solana_private_key_bytes():
    # Valid 32-byte private key
    private_key_bytes = bytes(range(32))
    parsed_key = parse_solana_private_key(private_key_bytes)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32
    assert parsed_key == private_key_bytes

    # Invalid private key (too short)
    with pytest.raises(
        ValueError, match="The private key in bytes must be exactly 32 bytes long."
    ):
        parse_solana_private_key(bytes(range(31)))


def test_parse_solana_private_key_base58():
    # Valid base58 private key (32 bytes)
    base58_key = base58.b58encode(bytes(range(32))).decode("utf-8")
    parsed_key = parse_solana_private_key(base58_key)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32

    # Invalid base58 key (not decodable)
    with pytest.raises(ValueError, match="Invalid base58 encoded private key"):
        parse_solana_private_key("invalid_base58_key")

    # Invalid base58 key (wrong length)
    with pytest.raises(
        ValueError,
        match="The base58 decoded private key must be either 32 or 64 bytes long.",
    ):
        parse_solana_private_key(base58.b58encode(bytes(range(31))).decode("utf-8"))


def test_parse_solana_private_key_list():
    # Valid list of uint8 integers (64 elements, but we only take the first 32 for private key)
    uint8_list = list(range(64))
    parsed_key = parse_solana_private_key(uint8_list)
    assert isinstance(parsed_key, bytes)
    assert len(parsed_key) == 32
    assert parsed_key == bytes(range(32))

    # Invalid list (contains non-integers)
    with pytest.raises(ValueError, match="Invalid uint8 array"):
        parse_solana_private_key([1, 2, "not an int", 4])  # type: ignore  # Ignore type check for string

    # Invalid list (less than 32 elements)
    with pytest.raises(
        ValueError, match="The uint8 array must contain at least 32 elements."
    ):
        parse_solana_private_key(list(range(31)))


def test_is_solana_private_key():
    sol_key = base58.b58encode(bytes(range(64))).decode("utf-8")
    assert is_valid_private_key(sol_key, SOLAccount) is True

    short_sol_key = base58.b58encode(bytes(range(32))).decode("utf-8")
    assert is_valid_private_key(short_sol_key, SOLAccount) is False

    sol_key_list = list(range(64))
    assert is_valid_private_key(sol_key_list, SOLAccount) is True

    short_sol_key_list = list(range(32))
    assert is_valid_private_key(short_sol_key_list, SOLAccount) is False

    sol_key_bytes = bytes(range(64))
    assert is_valid_private_key(sol_key_bytes, SOLAccount) is True

    short_sol_key_bytes = bytes(range(32))
    assert is_valid_private_key(short_sol_key_bytes, SOLAccount) is False


def test_detect_chain_from_private_key():
    eth_key = "0x" + "a" * 64
    assert detect_chain_from_private_key(eth_key) == Chain.ETH

    sol_key = base58.b58encode(bytes(range(64))).decode("utf-8")
    assert detect_chain_from_private_key(sol_key) == Chain.SOL

    sol_key_list = list(range(64))
    assert detect_chain_from_private_key(sol_key_list) == Chain.SOL

    with pytest.raises(ValueError, match="Unsupported private key format"):
        detect_chain_from_private_key("invalid_key")


def test_is_eth_private_key():
    eth_key = "0x" + "a" * 64
    assert is_valid_private_key(eth_key, ETHAccount) is True

    eth_key_no_prefix = "a" * 64
    assert is_valid_private_key(eth_key_no_prefix, ETHAccount) is True

    assert is_valid_private_key("a" * 63, ETHAccount) is False

    assert is_valid_private_key("zz" * 32, ETHAccount) is False

    eth_key_bytes = bytes(range(32))
    assert is_valid_private_key(eth_key_bytes, ETHAccount) is True

    assert is_valid_private_key(bytes(range(31)), ETHAccount) is False
