"""Tests for authenticated IPFS uploads (client-side CID computation).

Golden CIDs come from the aleph-cid test suite, which pins them against real
kubo (v0.30.0): the same fixtures must produce the same CIDs here.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock

import aleph_cid
import pytest
from aleph_message.models import ItemType, StoreMessage
from aleph_message.status import MessageStatus

from aleph.sdk.types import StorageEnum

# kubo `ipfs add` of an empty file (CIDv0)
GOLDEN_EMPTY_FILE_V0 = "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
# kubo /api/v0/add?wrap-with-directory=true of the nested fixture below (CIDv1)
GOLDEN_NESTED_DIR_V1 = "bafybeidcclyz24mrl4furbaf4ecb3ks52dbfer7r6dxqavd4wrqg7bp7lu"


def fixture_nested_dir(root: Path):
    (root / "top.txt").write_bytes(b"top\n")
    sub = root / "sub"
    sub.mkdir()
    (sub / "inner.txt").write_bytes(b"inner\n")
    deeper = sub / "deeper"
    deeper.mkdir()
    (deeper / "leaf.txt").write_bytes(b"leaf\n")


def posted_form_fields(http_session, url: str) -> dict:
    """Return {field_name: (headers, value)} of the multipart form posted to `url`."""
    for call in http_session.post.call_args_list:
        if call.args and call.args[0] == url:
            form = call.kwargs["data"]
            return {
                type_options["name"]: (headers, value)
                for type_options, headers, value in form._fields
            }
    raise AssertionError(f"No POST to {url}")


def test_golden_cid_vector():
    assert aleph_cid.compute_cid(b"") == GOLDEN_EMPTY_FILE_V0


@pytest.mark.asyncio
async def test_create_store_ipfs_authenticated(mock_session_with_post_success):
    content = b"Test authenticated ipfs upload\n"
    expected_cid = aleph_cid.compute_cid(content)
    assert expected_cid.startswith("Qm")

    async with mock_session_with_post_success as session:
        message, status = await session.create_store(
            file_content=content,
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

    assert isinstance(message, StoreMessage)
    assert status == MessageStatus.PENDING
    assert message.content.item_type == ItemType.ipfs
    assert message.content.item_hash == expected_cid
    assert message.signature

    # The file and the signed message must travel in one multipart request.
    fields = posted_form_fields(
        mock_session_with_post_success.http_session, "/api/v0/ipfs/add_file"
    )
    assert fields["file"][1].read() == content
    metadata = json.loads(fields["metadata"][1])
    assert metadata["sync"] is False
    assert metadata["message"]["signature"] == message.signature
    assert json.loads(metadata["message"]["item_content"])["item_hash"] == expected_cid


@pytest.mark.asyncio
async def test_create_store_ipfs_falls_back_without_aleph_cid(
    mock_session_with_post_success, monkeypatch
):
    monkeypatch.setattr("aleph.sdk.client.authenticated_http.aleph_cid", None)
    mock_ipfs_push_file = AsyncMock()
    mock_ipfs_push_file.return_value = GOLDEN_EMPTY_FILE_V0
    mock_session_with_post_success.ipfs_push_file = mock_ipfs_push_file

    async with mock_session_with_post_success as session:
        message, _ = await session.create_store(
            file_content=b"",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

    mock_ipfs_push_file.assert_called_once()
    assert message.content.item_hash == GOLDEN_EMPTY_FILE_V0


@pytest.mark.asyncio
async def test_create_store_folder(mock_session_with_post_success, tmp_path):
    folder = tmp_path / "site"
    folder.mkdir()
    fixture_nested_dir(folder)

    async with mock_session_with_post_success as session:
        message, status = await session.create_store_folder(
            folder_path=folder,
            channel="TEST",
        )

    assert isinstance(message, StoreMessage)
    assert status == MessageStatus.PENDING
    assert message.content.item_type == ItemType.ipfs
    assert message.content.item_hash == GOLDEN_NESTED_DIR_V1
    assert message.signature

    fields = posted_form_fields(
        mock_session_with_post_success.http_session, "/api/v0/ipfs/add_car"
    )
    metadata = json.loads(fields["metadata"][1])
    assert (
        json.loads(metadata["message"]["item_content"])["item_hash"]
        == GOLDEN_NESTED_DIR_V1
    )

    # The uploaded CAR must be a valid CARv1 whose root is the message CID.
    car_headers, car_value = fields["file"]
    assert car_headers.get("Content-Type") == "application/vnd.ipld.car"
    car_file = tmp_path / "roundtrip.car"
    car_file.write_bytes(car_value.read())
    assert aleph_cid.read_carv1_root(car_file) == GOLDEN_NESTED_DIR_V1


@pytest.mark.asyncio
async def test_create_store_folder_rejects_files(
    mock_session_with_post_success, tmp_path
):
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_bytes(b"x")
    async with mock_session_with_post_success as session:
        with pytest.raises(ValueError):
            await session.create_store_folder(folder_path=not_a_dir)
