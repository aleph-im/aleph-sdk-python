import hashlib
import json

import pytest
from aleph_message.models import MessageType, VerifiableProgramMessage

from aleph.sdk.query.filters import MessageFilter

from .conftest import make_mock_get_session

ADDRESS = "0x4145f182EF2F06b45E50468519C1B92C60FBd4A0"
LAUNCH_DIGEST = "e" * 96


def make_v_program_message() -> dict:
    content = {
        "address": ADDRESS,
        "time": 1755000000.0,
        "allow_amend": False,
        "payment": {"chain": "ETH", "type": "credit"},
        "resources": {"vcpus": 1, "memory": 512, "seconds": 30},
        "runtime": {"ref": "a" * 64, "comment": "runtime manifest"},
        "workload": {"ref": "b" * 64, "hash_tree": "c" * 64, "roothash": "d" * 64},
        "verification": {
            "backend": "sev_snp",
            "policy": 0x30000,
            "measurements": [
                {"platform": "sev_snp", "registers": {"launch": LAUNCH_DIGEST}}
            ],
        },
        "volumes": [],
        "environment": {"internet": True},
    }
    item_content = json.dumps(content, separators=(",", ":"))
    return {
        "chain": "ETH",
        "sender": ADDRESS,
        "type": "V-PROGRAM",
        "channel": "TEST",
        "time": 1755000000.0,
        "item_type": "inline",
        "item_content": item_content,
        "item_hash": hashlib.sha256(item_content.encode()).hexdigest(),
        "content": content,
        "signature": "0x" + "ab" * 65,
        "confirmed": False,
    }


@pytest.mark.asyncio
async def test_get_v_program_messages():
    raw = make_v_program_message()
    mock_session = make_mock_get_session(
        {
            "messages": [raw],
            "pagination_page": 1,
            "pagination_total": 1,
            "pagination_per_page": 20,
            "pagination_item": "messages",
        }
    )
    async with mock_session as session:
        response = await session.get_messages(
            message_filter=MessageFilter(message_types=[MessageType.v_program]),
            ignore_invalid_messages=False,
        )

    assert len(response.messages) == 1
    message = response.messages[0]
    assert isinstance(message, VerifiableProgramMessage)
    assert message.type == MessageType.v_program
    assert message.content.verification.measurements[0].registers.launch == (
        LAUNCH_DIGEST
    )


@pytest.mark.asyncio
async def test_get_v_program_message():
    raw = make_v_program_message()
    mock_session = make_mock_get_session({"status": "processed", "message": raw})
    async with mock_session as session:
        message = await session.get_message(
            raw["item_hash"], message_type=VerifiableProgramMessage
        )

    assert isinstance(message, VerifiableProgramMessage)
    assert message.content.workload.roothash == "d" * 64
    assert message.content.is_confidential


def test_message_filter_v_program_http_params():
    params = MessageFilter(message_types=[MessageType.v_program]).as_http_params()
    assert params["msgTypes"] == "V-PROGRAM"
