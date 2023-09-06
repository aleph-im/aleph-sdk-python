import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import List

import pytest as pytest
from aleph_message.models import AggregateMessage, AlephMessage, PostMessage

import aleph.sdk.chains.ethereum as ethereum
import aleph.sdk.chains.sol as solana
import aleph.sdk.chains.substrate as substrate
import aleph.sdk.chains.tezos as tezos
from aleph.sdk.chains.common import get_fallback_private_key


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
def messages() -> List[AlephMessage]:
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
def raw_messages_response(messages):
    return lambda page: {
        "messages": [message.dict() for message in messages] if page == 1 else [],
        "pagination_item": "messages",
        "pagination_page": page,
        "pagination_per_page": max(len(messages), 20),
        "pagination_total": len(messages) if page == 1 else 0,
    }
