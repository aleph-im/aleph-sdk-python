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
from aleph.sdk.client.message_cache import MessageCache
from aleph.sdk.db.post import message_to_post
from aleph.sdk.exceptions import MessageNotFoundError
from aleph.sdk.query.filters import MessageFilter, PostFilter


@pytest.mark.asyncio
async def test_base(aleph_messages):
    # test add_many
    cache = MessageCache()
    cache.add(aleph_messages)
    assert len(cache) >= len(aleph_messages)

    item_hashes = [message.item_hash for message in aleph_messages]
    cached_messages = cache.get(item_hashes)
    assert len(cached_messages) == len(aleph_messages)

    for message in aleph_messages:
        assert cache[message.item_hash] == message

    for message in aleph_messages:
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
    def class_setup(self, aleph_messages):
        self.messages = aleph_messages
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
        assert (
            self.messages[0]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(
                        addresses=[self.messages[0].sender],
                    )
                )
            ).messages
        )

    @pytest.mark.asyncio
    async def test_tags(self):
        assert (
            len(
                (
                    await self.cache.get_messages(
                        message_filter=MessageFilter(tags=["thistagdoesnotexist"])
                    )
                ).messages
            )
            == 0
        )

    @pytest.mark.asyncio
    async def test_message_type(self):
        assert (
            self.messages[1]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(message_types=[MessageType.post])
                )
            ).messages
        )

    @pytest.mark.asyncio
    async def test_refs(self):
        assert (
            self.messages[1]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(refs=[self.messages[1].content.ref])
                )
            ).messages
        )

    @pytest.mark.asyncio
    async def test_hashes(self):
        assert (
            self.messages[0]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(hashes=[self.messages[0].item_hash])
                )
            ).messages
        )

    @pytest.mark.asyncio
    async def test_pagination(self):
        assert len((await self.cache.get_messages(pagination=1)).messages) == 1

    @pytest.mark.asyncio
    async def test_content_types(self):
        assert (
            self.messages[1]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(
                        content_types=[self.messages[1].content.type]
                    )
                )
            ).messages
        )

    @pytest.mark.asyncio
    async def test_channels(self):
        assert (
            self.messages[1]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(channels=[self.messages[1].channel])
                )
            ).messages
        )

    @pytest.mark.asyncio
    async def test_chains(self):
        assert (
            self.messages[1]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(chains=[self.messages[1].chain])
                )
            ).messages
        )

    @pytest.mark.asyncio
    async def test_content_keys(self):
        assert (
            self.messages[0]
            in (
                await self.cache.get_messages(
                    message_filter=MessageFilter(
                        content_keys=[self.messages[0].content.key]
                    )
                )
            ).messages
        )


class TestPostQueries:
    messages: List[AlephMessage]
    cache: MessageCache

    @pytest.fixture(autouse=True)
    def class_setup(self, aleph_messages):
        self.messages = aleph_messages
        self.cache = MessageCache()
        self.cache.add(self.messages)

    def class_teardown(self):
        del self.cache

    @pytest.mark.asyncio
    async def test_addresses(self):
        assert (
            message_to_post(self.messages[1])
            in (
                await self.cache.get_posts(
                    post_filter=PostFilter(addresses=[self.messages[1].sender])
                )
            ).posts
        )

    @pytest.mark.asyncio
    async def test_tags(self):
        assert (
            len(
                (
                    await self.cache.get_posts(
                        post_filter=PostFilter(tags=["thistagdoesnotexist"])
                    )
                ).posts
            )
            == 0
        )

    @pytest.mark.asyncio
    async def test_types(self):
        assert (
            len(
                (
                    await self.cache.get_posts(
                        post_filter=PostFilter(types=["thistypedoesnotexist"])
                    )
                ).posts
            )
            == 0
        )

    @pytest.mark.asyncio
    async def test_channels(self):
        assert (
            message_to_post(self.messages[1])
            in (
                await self.cache.get_posts(
                    post_filter=PostFilter(channels=[self.messages[1].channel])
                )
            ).posts
        )

    @pytest.mark.asyncio
    async def test_chains(self):
        assert (
            message_to_post(self.messages[1])
            in (
                await self.cache.get_posts(
                    post_filter=PostFilter(chains=[self.messages[1].chain])
                )
            ).posts
        )


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
                signature="",
            )
            yield message

    cache = MessageCache()
    # test listener
    coro = cache.listen_to(mock_message_stream())
    await coro
    assert len(cache) >= 3


@pytest.mark.asyncio
async def test_fetch_aggregate(aleph_messages):
    cache = MessageCache()
    cache.add(aleph_messages)

    aggregate = await cache.fetch_aggregate(
        aleph_messages[0].sender, aleph_messages[0].content.key
    )

    print(aggregate)

    assert aggregate == aleph_messages[0].content.content


@pytest.mark.asyncio
async def test_fetch_aggregates(aleph_messages):
    cache = MessageCache()
    cache.add(aleph_messages)

    aggregates = await cache.fetch_aggregates(aleph_messages[0].sender)

    assert aggregates == {
        aleph_messages[0].content.key: aleph_messages[0].content.content
    }


@pytest.mark.asyncio
async def test_get_message(aleph_messages):
    cache = MessageCache()
    cache.add(aleph_messages)

    message: AlephMessage = await cache.get_message(aleph_messages[0].item_hash)

    assert message == aleph_messages[0]


@pytest.mark.asyncio
async def test_get_message_fail():
    cache = MessageCache()

    with pytest.raises(MessageNotFoundError):
        await cache.get_message("0x1234567890123456789012345678901234567890")
