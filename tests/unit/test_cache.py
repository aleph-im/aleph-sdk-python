import json
from hashlib import sha256
from typing import List

import pytest
from aleph_message.models import (
    AggregateMessage,
    AlephMessage,
    Chain,
    MessageType,
    PostContent,
    PostMessage,
)

from aleph.sdk.cache import MessageCache
from aleph.sdk.chains.ethereum import get_fallback_account


@pytest.fixture(scope="session")
def messages():
    return [
        AggregateMessage.parse_obj(
            {
                "item_hash": "5b26d949fe05e38f535ef990a89da0473f9d700077cced228f2d36e73fca1fd6",
                "type": "AGGREGATE",
                "chain": "ETH",
                "sender": "0x51A58800b26AA1451aaA803d1746687cB88E0501",
                "signature": "0xca5825b6b93390482b436cb7f28b4628f8c9f56dc6af08260c869b79dd6017c94248839bd9fd0ffa1230dc3b1f4f7572a8d1f6fed6c6e1fb4d70ccda0ab5d4f21b",
                "item_type": "inline",
                "item_content": '{"address":"0x51A58800b26AA1451aaA803d1746687cB88E0501","key":"0xce844d79e5c0c325490c530aa41e8f602f0b5999binance","content":{"1692026263168":{"version":"x25519-xsalsa20-poly1305","nonce":"RT4Lbqs7Xzk+op2XC+VpXgwOgg21BotN","ephemPublicKey":"CVW8ECE3m8BepytHMTLan6/jgIfCxGdnKmX47YirF08=","ciphertext":"VuGJ9vMkJSbaYZCCv6Zemx4ixeb+9IW8H1vFB9vLtz1a8d87R4BfYUisLoCQxRkeUXqfW0/KIGQ5idVjr8Yj7QnKglW5AJ8UX7wEWMhiRFLatpWP8P9FI2n8Z7Rblu7Oz/OeKnuljKL3KsalcUQSsFa/1qACsIoycPZ6Wq6t1mXxVxxJWzClLyKRihv1pokZGT9UWxh7+tpoMGlRdYainyAt0/RygFw+r8iCMOilHnyv4ndLkKQJXyttb0tdNr/gr57+9761+trioGSysLQKZQWW6Ih6aE8V9t3BenfzYwiCnfFw3YAAKBPMdm9QdIETyrOi7YhD/w==","sha256":"bbeb499f681aed2bc18b6f3b6a30d25254bd30fbfde43444e9085f3bcd075c3c"}},"time":1692026263.662}',
                "content": {
                    "key": "0xce844d79e5c0c325490c530aa41e8f602f0b5999binance",
                    "time": 1692026263.662,
                    "address": "0x51A58800b26AA1451aaA803d1746687cB88E0501",
                    "content": {
                        "hello": "world",
                    },
                },
                "time": 1692026263.662,
                "channel": "UNSLASHED",
                "size": 734,
                "confirmations": [],
                "confirmed": False,
            }
        ),
        PostMessage.parse_obj(
            {
                "item_hash": "70f3798fdc68ce0ee03715a5547ee24e2c3e259bf02e3f5d1e4bf5a6f6a5e99f",
                "type": "POST",
                "chain": "SOL",
                "sender": "0x4D52380D3191274a04846c89c069E6C3F2Ed94e4",
                "signature": "0x91616ee45cfba55742954ff87ebf86db4988bcc5e3334b49a4caa6436e28e28d4ab38667cbd4bfb8903abf8d71f70d9ceb2c0a8d0a15c04fc1af5657f0050c101b",
                "item_type": "storage",
                "item_content": None,
                "content": {
                    "time": 1692026021.1257718,
                    "type": "aleph-network-metrics",
                    "address": "0x4D52380D3191274a04846c89c069E6C3F2Ed94e4",
                    "ref": "0123456789abcdef",
                    "content": {
                        "tags": ["mainnet"],
                        "hello": "world",
                        "version": "1.0",
                    },
                },
                "time": 1692026021.132849,
                "channel": "aleph-scoring",
                "size": 122537,
                "confirmations": [],
                "confirmed": False,
            }
        ),
    ]


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
