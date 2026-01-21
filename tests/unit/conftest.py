import asyncio
import json
from functools import wraps
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Callable, Dict, List, Optional, Union
from unittest.mock import AsyncMock, MagicMock

import pytest as pytest
from aiohttp import ClientResponseError
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
        AggregateMessage.model_validate(
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
        PostMessage.model_validate(
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
            [message.model_dump() for message in aleph_messages]
            if int(page) == 1
            else []
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


@pytest.fixture
def address_stats_data() -> List[Dict[str, Any]]:
    return [
        {
            "address": "0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10",
            "post": 10,
            "aggregate": 5,
            "store": 3,
            "forget": 0,
            "program": 2,
            "instance": 1,
            "total": 21,
        },
        {
            "address": "0x51A58800b26AA1451aaA803d1746687cB88E0501",
            "post": 15,
            "aggregate": 8,
            "store": 6,
            "forget": 1,
            "program": 3,
            "instance": 2,
            "total": 35,
        },
    ]


@pytest.fixture
def raw_address_stats_response(
    address_stats_data,
) -> Callable[[int], Dict[str, Any]]:
    # Convert list of address stats to dict format as returned by API
    data_dict = {}
    if int(1) == 1:  # page 1
        for item in address_stats_data:
            address = item["address"]
            data_dict[address] = {
                "messages": item["total"],
                "post": item["post"],
                "aggregate": item["aggregate"],
                "store": item["store"],
                "forget": item["forget"],
                "program": item["program"],
                "instance": item["instance"],
            }

    return lambda page: {
        "data": data_dict if int(page) == 1 else {},
        "pagination_item": "addresses",
        "pagination_page": int(page),
        "pagination_per_page": max(len(address_stats_data), 20),
        "pagination_total": len(address_stats_data) if page == 1 else 0,
    }


@pytest.fixture
def address_files_data() -> Dict[str, Any]:
    return {
        "address": "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B24d",
        "total_size": 2048000,
        "files": [
            {
                "file_hash": "QmX1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1",
                "size": 1024000,
                "type": "file",
                "created": "2024-01-15T10:30:00.000000",
                "item_hash": "abc123def456",
            },
            {
                "file_hash": "QmY9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0g9",
                "size": 1024000,
                "type": "directory",
                "created": "2024-01-16T14:45:00.000000",
                "item_hash": "xyz789uvw012",
            },
        ],
        "pagination_page": 1,
        "pagination_total": 2,
        "pagination_per_page": 100,
        "pagination_item": "files",
    }


@pytest.fixture
def chain_balances_data() -> List[Dict[str, Any]]:
    """Return mock data representing chain balances."""
    return [
        {
            "address": "0x1234567890123456789012345678901234567890",
            "balance": 1000.5,
            "chain": "ETH",
        },
        {
            "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "balance": 2500.75,
            "chain": "ETH",
        },
        {
            "address": "0x9876543210987654321098765432109876543210",
            "balance": 500.0,
            "chain": "AVAX",
        },
    ]


@pytest.fixture
def raw_chain_balances_response(
    chain_balances_data: List[Dict[str, Any]],
) -> Callable[[int], Dict[str, Any]]:
    """Return a function that generates paginated chain balances API responses."""

    return lambda page: {
        "balances": chain_balances_data if int(page) == 1 else [],
        "pagination_item": "balances",
        "pagination_page": int(page),
        "pagination_per_page": 100,
        "pagination_total": len(chain_balances_data) if page == 1 else 0,
    }


class MockResponse:
    def __init__(self, sync: bool):
        self.sync = sync

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb): ...

    def raise_for_status(self): ...

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

        def raise_for_status(self):
            if status >= 400:
                raise ClientResponseError(None, None, status=status)

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


def make_mock_get_session_400(
    get_return_value: Union[Dict[str, Any], bytes]
) -> AlephHttpClient:
    class MockHttpSession(AsyncMock):
        def get(self, *_args, **_kwargs):
            return make_custom_mock_response(get_return_value, 400)

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


@pytest.fixture
def make_mock_aiohttp_session():
    def _make(mocked_json_response):
        mock_response = AsyncMock()
        mock_response.json.return_value = mocked_json_response
        mock_response.raise_for_status.return_value = None

        session = MagicMock()

        get_cm = AsyncMock()
        get_cm.__aenter__.return_value = mock_response
        session.get.return_value = get_cm

        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = session
        return session_cm

    return _make


# Constants needed for voucher tests
MOCK_ADDRESS = "0x1234567890123456789012345678901234567890"
MOCK_SOLANA_ADDRESS = "abcdefghijklmnopqrstuvwxyz123456789"
MOCK_METADATA_ID = "metadata123"
MOCK_VOUCHER_ID = "voucher123"
MOCK_METADATA = {
    "name": "Test Voucher",
    "description": "A test voucher",
    "external_url": "https://example.com",
    "image": "https://example.com/image.png",
    "icon": "https://example.com/icon.png",
    "attributes": [
        {"trait_type": "Test Trait", "value": "Test Value"},
        {"trait_type": "Numeric Trait", "value": "123", "display_type": "number"},
    ],
}

MOCK_EVM_VOUCHER_DATA = [
    (MOCK_VOUCHER_ID, {"claimer": MOCK_ADDRESS, "metadata_id": MOCK_METADATA_ID})
]

MOCK_SOLANA_REGISTRY = {
    "claimed_tickets": {
        "solticket123": {"claimer": MOCK_SOLANA_ADDRESS, "batch_id": "batch123"}
    },
    "batches": {"batch123": {"metadata_id": MOCK_METADATA_ID}},
}


@pytest.fixture
def mock_post_response():
    mock_post = MagicMock()
    mock_post.content = {
        "nft_vouchers": {
            MOCK_VOUCHER_ID: {"claimer": MOCK_ADDRESS, "metadata_id": MOCK_METADATA_ID}
        }
    }
    posts_response = MagicMock()
    posts_response.posts = [mock_post]
    return posts_response
