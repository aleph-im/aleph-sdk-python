import asyncio
from typing import Tuple

import pytest
from aleph_message.models import ItemHash

from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import Account

from .config import REFERENCE_NODE, TARGET_NODE, TEST_CHANNEL
from .toolkit import has_messages, has_no_messages, try_until


async def create_and_forget_post(
    account: Account, emitter_node: str, receiver_node: str, channel=TEST_CHANNEL
) -> Tuple[ItemHash, ItemHash]:
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=emitter_node
    ) as tx_session:
        post_message, message_status = await tx_session.create_post(
            post_content="A considerate and politically correct post.",
            post_type="POST",
            channel="INTEGRATION_TESTS",
        )

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=receiver_node
    ) as rx_session:
        await try_until(
            rx_session.get_messages,
            has_messages,
            timeout=5,
            message_filter=MessageFilter(
                hashes=[post_message.item_hash],
            ),
        )

    post_hash = post_message.item_hash
    reason = "This well thought-out content offends me!"
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=emitter_node
    ) as tx_session:
        forget_message, forget_status = await tx_session.forget(
            hashes=[post_hash],
            reason=reason,
            channel=channel,
        )
    assert forget_message.sender == account.get_address()
    assert forget_message.content.reason == reason
    assert forget_message.content.hashes == [post_hash]
    forget_hash = forget_message.item_hash

    # Wait until the message is forgotten
    async with AuthenticatedAlephHttpClient(
        account=account, api_server=receiver_node
    ) as rx_session:
        await try_until(
            rx_session.get_messages,
            has_messages,
            timeout=5,
            message_filter=MessageFilter(
                hashes=[forget_hash],
            ),
        )

        await try_until(
            rx_session.get_messages,
            has_no_messages,
            timeout=5,
            message_filter=MessageFilter(
                hashes=[post_hash],
            ),
        )

    return post_hash, forget_hash


@pytest.mark.asyncio
async def test_create_and_forget_post_on_target(fixture_account):
    """
    Create a post on the target node, then forget it and check that the change is propagated
    to the reference node.
    """
    _, _ = await create_and_forget_post(fixture_account, TARGET_NODE, REFERENCE_NODE)


@pytest.mark.asyncio
async def test_create_and_forget_post_on_reference(fixture_account):
    """
    Create a post on the reference node, then forget it and check that the change is propagated
    to the target node.
    """
    _, _ = await create_and_forget_post(fixture_account, REFERENCE_NODE, TARGET_NODE)


@pytest.mark.asyncio
async def test_forget_a_forget_message(fixture_account):
    """
    Attempts to forget a forget message. This should fail.
    """

    # TODO: this test should be moved to the PyAleph API tests, once a framework is in place.
    post_hash, forget_hash = await create_and_forget_post(
        fixture_account, TARGET_NODE, REFERENCE_NODE
    )
    async with AuthenticatedAlephHttpClient(
        account=fixture_account, api_server=TARGET_NODE
    ) as tx_session:
        forget_message, forget_status = await tx_session.forget(
            hashes=[forget_hash],
            reason="I want to remember this post. Maybe I can forget I forgot it?",
            channel=TEST_CHANNEL,
        )

        print(forget_message)

    # wait 5 seconds
    await asyncio.sleep(5)

    async with AuthenticatedAlephHttpClient(
        account=fixture_account, api_server=REFERENCE_NODE
    ) as rx_session:
        get_forget_message_response = await try_until(
            rx_session.get_messages,
            has_messages,
            timeout=5,
            message_filter=MessageFilter(
                hashes=[forget_hash],
            ),
        )
        assert len(get_forget_message_response.messages) == 1
        forget_message = get_forget_message_response.messages[0]
        print(forget_message)

        assert "forgotten_by" not in forget_message
