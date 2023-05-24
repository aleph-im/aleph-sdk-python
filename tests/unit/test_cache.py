import asyncio

import pytest

from aleph.sdk.cache import MessageCache
from aleph.sdk.chains.ethereum import get_fallback_account
from aleph.sdk.client import AlephClient, AuthenticatedAlephClient
from aleph.sdk.conf import settings


@pytest.mark.asyncio
async def test_message_cache():
    session = AlephClient(settings.API_HOST)
    messages = (await session.get_messages()).messages

    # test add_many
    cache = MessageCache()
    cache.add_many(messages)

    # test get_many
    item_hashes = [message.item_hash for message in messages]
    cached_messages = cache.get_many(item_hashes)
    assert len(cached_messages) == len(messages)

    # test __getitem__
    for message in messages:
        assert cache[message.item_hash] == message

    # test __contains__
    for message in messages:
        assert message.item_hash in cache

    # test query with senders
    senders = set(message.sender for message in messages)
    items = (await cache.get_messages(addresses=senders)).messages
    assert len(items) == len(messages)
    # with tags
    items = (
        await cache.get_messages(
            addresses=senders, tags=["thistagwillprobablyneverexist"]
        )
    ).messages
    assert len(items) == 0


@pytest.mark.asyncio
async def test_message_cache_listener():
    auth_session = AuthenticatedAlephClient(get_fallback_account(), settings.API_HOST)
    cache = MessageCache()

    # test listen until first message
    coro = cache.listen_to(auth_session.watch_messages())
    task = asyncio.create_task(coro)
    before = len(cache)
    # send message
    await auth_session.create_aggregate("test", {"test": "test"})
    await asyncio.sleep(2)  # wait for message to be received
    task.cancel()
    after = len(cache)
    assert after > before
