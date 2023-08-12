import asyncio
import json
from hashlib import sha256

import pytest
from aleph_message.models import AlephMessage, PostMessage, PostContent, MessageType, Chain

from aleph.sdk.cache import MessageCache
from aleph.sdk.chains.ethereum import get_fallback_account
from aleph.sdk.client import AlephClient, AuthenticatedAlephClient
from aleph.sdk.conf import settings


@pytest.mark.asyncio
async def test_message_cache():
    session = AlephClient(settings.API_HOST)
    # TODO: Mock response
    messages = (await session.get_messages()).messages

    # test add_many
    cache = MessageCache()
    cache.add(messages)

    # test get_many
    item_hashes = [message.item_hash for message in messages]
    cached_messages = cache.get(item_hashes)
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
    async def mock_message_stream():
        for i in range(3):
            content = PostContent(
                    content={"hello": f"world{i}"},
                    type="test",
                    address=get_fallback_account().get_address(),
                    time=0,
                )
            message = PostMessage(
                sender=get_fallback_account().get_address(),
                item_hash=sha256(json.dumps(content.dict()).encode()).hexdigest(),
                chain=Chain.ETH.value,
                type=MessageType.post.value,
                item_type="inline",
                time=0,
                content=content,
                item_content=json.dumps(content.dict()),
            )
            yield message
    cache = MessageCache()
    # test listener
    coro = cache.listen_to(mock_message_stream())
    await coro
    assert len(cache) == 3
