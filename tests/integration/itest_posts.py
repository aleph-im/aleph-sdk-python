import pytest
import time # Used for unique content generation

from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.query.filters import MessageFilter
from tests.integration.toolkit import has_messages, try_until

# Import configuration constants, assumed to be defined externally.
from .config import REFERENCE_NODE, TARGET_NODE, DEFAULT_TIMEOUT_SECONDS

# Set a common channel for all integration tests
INTEGRATION_CHANNEL = "INTEGRATION_TESTS"


async def create_and_verify_message(account, emitter_node: str, receiver_node: str):
    """
    Creates a POST message on the emitter node and verifies its successful
    propagation by fetching it from the receiver node.

    Args:
        account: The signing account fixture.
        emitter_node: The Aleph node used to send the transaction.
        receiver_node: The Aleph node used to verify the message retrieval.
    """
    # Use a unique message content for better isolation and debugging.
    test_content = {
        "context": "integration_test_propagation",
        "timestamp": time.time(),
        "emitter": emitter_node,
    }

    # --- 1. SEND MESSAGE on Emitter Node ---
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=emitter_node
    ) as tx_session:
        post_message, message_status = await tx_session.create_post(
            post_content=test_content,
            post_type="POST",
            channel=INTEGRATION_CHANNEL,
        )

    # --- 2. VERIFY MESSAGE on Receiver Node ---
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=receiver_node
    ) as rx_session:
        # Attempt to retrieve the message repeatedly until it appears, checking for propagation.
        responses = await try_until(
            rx_session.get_messages,
            has_messages,
            # Use a configurable or reasonable default timeout for network propagation tests.
            timeout=DEFAULT_TIMEOUT_SECONDS, 
            message_filter=MessageFilter(
                hashes=[post_message.item_hash],
            ),
        )

    # Assert that the received message hash matches the sent message hash.
    message_from_target = responses.messages[0]
    assert post_message.item_hash == message_from_target.item_hash
    # Optional: Verify content integrity
    assert message_from_target.content == test_content


@pytest.mark.asyncio
async def test_create_message_on_target_to_reference(fixture_account):
    """
    Tests propagation by sending a message to the TARGET_NODE and receiving it
    from the REFERENCE_NODE. (T -> R)
    """
    await create_and_verify_message(
        fixture_account, emitter_node=TARGET_NODE, receiver_node=REFERENCE_NODE
    )


@pytest.mark.asyncio
async def test_create_message_on_reference_to_target(fixture_account):
    """
    Tests propagation by sending a message to the REFERENCE_NODE and receiving it
    from the TARGET_NODE. (R -> T)
    """
    await create_and_verify_message(
        fixture_account, emitter_node=REFERENCE_NODE, receiver_node=TARGET_NODE
    )
