import json
from hashlib import sha256
from typing import List

import pytest
from aleph_message.models import (
    AlephMessage,
    Chain,
    MessageType,
    PostContent,
    PostMessage,
)

from aleph.sdk.chains.ethereum import get_fallback_account
from aleph.sdk.exceptions import MessageNotFoundError
from aleph.sdk.node import MessageCache, message_to_post


@pytest.mark.asyncio
async def test_base(messages):
    # test add_many
    cache = MessageCache()
    cache.add(messages)
    assert len(cache) == len(messages)

    item_hashes = [message.item_hash for message in messages]
    cached_messages = cache.get(item_hashes)
    assert len(cached_messages) == len(messages)

    for message in messages:
        assert cache[message.item_hash] == message

    for message in messages:
        assert message.item_hash in cache

    for message in cache:
        del cache[message.item_hash]
        assert message.item_hash not in cache

    assert len(cache) == 0
    del cache


class TestMessageQueries:
    messages: List[AlephMessage]
    cache: MessageCache

    @pytest.fixture(autouse=True)
    def class_setup(self, messages):
        self.messages = messages
        self.cache = MessageCache()
        self.cache.add(self.messages)

    def class_teardown(self):
        del self.cache

    @pytest.mark.asyncio
    async def test_iterate(self):
        assert len(self.cache) == len(self.messages)
        for message in self.cache:
            assert message in self.messages

    @pytest.mark.asyncio
    async def test_addresses(self):
        items = (
            await self.cache.get_messages(addresses=[self.messages[0].sender])
        ).messages
        assert items[0] == self.messages[0]

    @pytest.mark.asyncio
    async def test_tags(self):
        assert (
            len((await self.cache.get_messages(tags=["thistagdoesnotexist"])).messages)
            == 0
        )

    @pytest.mark.asyncio
    async def test_message_type(self):
        assert (await self.cache.get_messages(message_type=MessageType.post)).messages[
            0
        ] == self.messages[1]

    @pytest.mark.asyncio
    async def test_refs(self):
        assert (
            await self.cache.get_messages(refs=[self.messages[1].content.ref])
        ).messages[0] == self.messages[1]

    @pytest.mark.asyncio
    async def test_hashes(self):
        assert (
            await self.cache.get_messages(hashes=[self.messages[0].item_hash])
        ).messages[0] == self.messages[0]

    @pytest.mark.asyncio
    async def test_pagination(self):
        assert len((await self.cache.get_messages(pagination=1)).messages) == 1

    @pytest.mark.asyncio
    async def test_content_types(self):
        assert (
            await self.cache.get_messages(content_types=[self.messages[1].content.type])
        ).messages[0] == self.messages[1]

    @pytest.mark.asyncio
    async def test_channels(self):
        assert (
            await self.cache.get_messages(channels=[self.messages[1].channel])
        ).messages[0] == self.messages[1]

    @pytest.mark.asyncio
    async def test_chains(self):
        assert (
            await self.cache.get_messages(chains=[self.messages[1].chain])
        ).messages[0] == self.messages[1]

    @pytest.mark.asyncio
    async def test_content_keys(self):
        assert (
            await self.cache.get_messages(content_keys=[self.messages[0].content.key])
        ).messages[0] == self.messages[0]


class TestPostQueries:
    messages: List[AlephMessage]
    cache: MessageCache

    @pytest.fixture(autouse=True)
    def class_setup(self, messages):
        self.messages = messages
        self.cache = MessageCache()
        self.cache.add(self.messages)

    def class_teardown(self):
        del self.cache

    @pytest.mark.asyncio
    async def test_addresses(self):
        items = (await self.cache.get_posts(addresses=[self.messages[1].sender])).posts
        assert items[0] == message_to_post(self.messages[1])

    @pytest.mark.asyncio
    async def test_tags(self):
        assert (
            len((await self.cache.get_posts(tags=["thistagdoesnotexist"])).posts) == 0
        )

    @pytest.mark.asyncio
    async def test_types(self):
        assert (
            len((await self.cache.get_posts(types=["thistypedoesnotexist"])).posts) == 0
        )

    @pytest.mark.asyncio
    async def test_channels(self):
        print(self.messages[1])
        assert (await self.cache.get_posts(channels=[self.messages[1].channel])).posts[
            0
        ] == message_to_post(self.messages[1])

    @pytest.mark.asyncio
    async def test_chains(self):
        assert (await self.cache.get_posts(chains=[self.messages[1].chain])).posts[
            0
        ] == message_to_post(self.messages[1])


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
    assert len(cache) >= 3


@pytest.mark.asyncio
async def test_fetch_aggregate(messages):
    cache = MessageCache()
    cache.add(messages)

    aggregate = await cache.fetch_aggregate(messages[0].sender, messages[0].content.key)

    assert aggregate == messages[0].content.content


@pytest.mark.asyncio
async def test_fetch_aggregates(messages):
    cache = MessageCache()
    cache.add(messages)

    aggregates = await cache.fetch_aggregates(messages[0].sender)

    assert aggregates == {messages[0].content.key: messages[0].content.content}


@pytest.mark.asyncio
async def test_get_message(messages):
    cache = MessageCache()
    cache.add(messages)

    message: AlephMessage = await cache.get_message(messages[0].item_hash)

    assert message == messages[0]


@pytest.mark.asyncio
async def test_get_message_fail():
    cache = MessageCache()

    with pytest.raises(MessageNotFoundError):
        await cache.get_message("0x1234567890123456789012345678901234567890")
