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

from aleph.sdk.cache import MessageCache
from aleph.sdk.chains.ethereum import get_fallback_account


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
            await self.cache.get_messages(addresses=self.messages[0].sender)
        ).messages
        assert items[0] == self.messages[0]

    @pytest.mark.asyncio
    async def test_tags(self):
        assert (
            len((await self.cache.get_messages(tags="thistagdoesnotexist")).messages)
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
            await self.cache.get_messages(refs=self.messages[1].content.ref)
        ).messages[0] == self.messages[1]

    @pytest.mark.asyncio
    async def test_hashes(self):
        assert (
            await self.cache.get_messages(hashes=self.messages[0].item_hash)
        ).messages[0] == self.messages[0]

    @pytest.mark.asyncio
    async def test_pagination(self):
        assert len((await self.cache.get_messages(pagination=1)).messages) == 1

    @pytest.mark.asyncio
    async def test_content_types(self):
        assert (
            await self.cache.get_messages(content_types=self.messages[1].content.type)
        ).messages[0] == self.messages[1]

    @pytest.mark.asyncio
    async def test_channels(self):
        assert (
            await self.cache.get_messages(channels=self.messages[1].channel)
        ).messages[0] == self.messages[1]

    @pytest.mark.asyncio
    async def test_chains(self):
        assert (await self.cache.get_messages(chains=self.messages[1].chain)).messages[
            0
        ] == self.messages[1]

    @pytest.mark.asyncio
    async def test_content_keys(self):
        assert (
            await self.cache.get_messages(content_keys=self.messages[0].content.key)
        ).messages[0] == self.messages[0]


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
