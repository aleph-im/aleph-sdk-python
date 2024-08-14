import asyncio
import json
from functools import wraps
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Callable, Dict, List, Optional, Union
from unittest.mock import AsyncMock, MagicMock

import pytest as pytest
from aleph_message.models import AggregateMessage, AlephMessage, PostMessage

import aleph.sdk.chains.ethereum as ethereum
import aleph.sdk.chains.solana as solana
import aleph.sdk.chains.substrate as substrate
import aleph.sdk.chains.tezos as tezos
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.types import Account


@pytest.fixture
def fallback_private_key() -> bytes:
    with NamedTemporaryFile() as private_key_file:
        yield get_fallback_private_key(path=Path(private_key_file.name))


@pytest.fixture
def ethereum_account() -> ethereum.ETHAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        yield ethereum.get_fallback_account(path=Path(private_key_file.name))


@pytest.fixture
def solana_account() -> solana.SOLAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        yield solana.get_fallback_account(path=Path(private_key_file.name))


@pytest.fixture
def tezos_account() -> tezos.TezosAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        yield tezos.get_fallback_account(path=Path(private_key_file.name))


@pytest.fixture
def substrate_account() -> substrate.DOTAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        yield substrate.get_fallback_account(path=Path(private_key_file.name))


@pytest.fixture
def json_messages():
    messages_path = Path(__file__).parent / "messages.json"
    with open(messages_path) as f:
        return json.load(f)


@pytest.fixture
def rejected_message():
    message_path = Path(__file__).parent / "rejected_message.json"
    with open(message_path) as f:
        return json.load(f)


@pytest.fixture
def aleph_messages() -> List[AlephMessage]:
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


@pytest.fixture
def json_post() -> dict:
    with open(Path(__file__).parent / "post.json", "r") as f:
        return json.load(f)


@pytest.fixture
def raw_messages_response(aleph_messages) -> Callable[[int], Dict[str, Any]]:
    return lambda page: {
        "messages": (
            [message.dict() for message in aleph_messages] if int(page) == 1 else []
        ),
        "pagination_item": "messages",
        "pagination_page": int(page),
        "pagination_per_page": max(len(aleph_messages), 20),
        "pagination_total": len(aleph_messages) if page == 1 else 0,
    }


@pytest.fixture
def raw_posts_response(json_post) -> Callable[[int], Dict[str, Any]]:
    return lambda page: {
        "posts": [json_post] if int(page) == 1 else [],
        "pagination_item": "posts",
        "pagination_page": int(page),
        "pagination_per_page": 1,
        "pagination_total": 1 if page == 1 else 0,
    }


class MockResponse:
    def __init__(self, sync: bool):
        self.sync = sync

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb): ...

    async def raise_for_status(self): ...

    @property
    def status(self):
        return 200 if self.sync else 202

    async def json(self):
        message_status = "processed" if self.sync else "pending"
        return {
            "message_status": message_status,
            "publication_status": {"status": "success", "failed": []},
        }

    async def text(self):
        return json.dumps(await self.json())


@pytest.fixture
def mock_session_with_post_success(
    ethereum_account: Account,
) -> AuthenticatedAlephHttpClient:
    http_session = AsyncMock()
    http_session.post = MagicMock()
    http_session.post.side_effect = lambda *args, **kwargs: MockResponse(
        sync=kwargs.get("sync", False)
    )

    client = AuthenticatedAlephHttpClient(
        account=ethereum_account, api_server="http://localhost"
    )
    client._http_session = http_session

    return client


def async_wrap(cls):
    class AsyncWrapper:
        def __init__(self, *args, **kwargs):
            self._instance = cls(*args, **kwargs)

        def __getattr__(self, item):
            attr = getattr(self._instance, item)
            if callable(attr):

                @wraps(attr)
                async def method(*args, **kwargs):
                    loop = asyncio.get_running_loop()
                    return await loop.run_in_executor(None, attr, *args, **kwargs)

                return method
            return attr

    return AsyncWrapper


AsyncBytesIO = async_wrap(BytesIO)


def make_custom_mock_response(
    resp: Union[Dict[str, Any], bytes], status=200
) -> MockResponse:
    class CustomMockResponse(MockResponse):
        content: Optional[AsyncBytesIO]

        async def json(self):
            return resp

        @property
        def status(self):
            return status

    mock = CustomMockResponse(sync=True)

    try:
        mock.content = AsyncBytesIO(resp)
    except Exception as e:
        print(e)

    return mock


def make_mock_get_session(
    get_return_value: Union[Dict[str, Any], bytes]
) -> AlephHttpClient:
    class MockHttpSession(AsyncMock):
        def get(self, *_args, **_kwargs):
            return make_custom_mock_response(get_return_value)

    http_session = MockHttpSession()

    client = AlephHttpClient(api_server="http://localhost")
    client._http_session = http_session

    return client


@pytest.fixture
def mock_session_with_rejected_message(
    ethereum_account, rejected_message
) -> AuthenticatedAlephHttpClient:
    class MockHttpSession(AsyncMock):
        def get(self, *_args, **_kwargs):
            return make_custom_mock_response(rejected_message)

        def post(self, *_args, **_kwargs):
            return make_custom_mock_response(
                {
                    "message_status": "rejected",
                    "publication_status": {"status": "success", "failed": []},
                },
                status=422,
            )

    http_session = MockHttpSession()

    client = AuthenticatedAlephHttpClient(
        account=ethereum_account, api_server="http://localhost"
    )
    client._http_session = http_session

    return client
