import pytest

from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.query.filters import MessageFilter
from tests.integration.toolkit import has_messages, try_until

from .config import REFERENCE_NODE, TARGET_NODE


async def create_store_on_target(account, emitter_node: str, receiver_node: str):
    """
    Create a POST message on the target node, then fetch it from the reference node and download the file.
    """
    with open("tests/integration/fixtures/testStore.txt", "rb") as f:
        file_content = f.read()
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=emitter_node
    ) as tx_session:
        store_message, message_status = await tx_session.create_store(
            file_content=file_content,
            extra_fields={"test": "test"},
        )

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=receiver_node
    ) as rx_session:
        responses = await try_until(
            rx_session.get_messages,
            has_messages,
            timeout=5,
            message_filter=MessageFilter(
                hashes=[store_message.item_hash],
            ),
        )

    message_from_target = responses.messages[0]
    assert store_message.item_hash == message_from_target.item_hash

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=receiver_node
    ) as rx_session:
        store_content = await rx_session.download_file(store_message.content.item_hash)
        assert store_content == file_content


@pytest.mark.asyncio
async def test_create_message_on_target(fixture_account):
    """
    Attempts to create a new message on the target node and verifies if the message can be fetched from
    the reference node.
    """
    await create_store_on_target(
        fixture_account, emitter_node=TARGET_NODE, receiver_node=REFERENCE_NODE
    )


@pytest.mark.asyncio
async def test_create_message_on_reference(fixture_account):
    """
    Attempts to create a new message on the reference node and verifies if the message can be fetched from
    the target node.
    """
    await create_store_on_target(
        fixture_account, emitter_node=REFERENCE_NODE, receiver_node=TARGET_NODE
    )
