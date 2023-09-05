import json
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest as pytest

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
def messages():
    messages_path = Path(__file__).parent / "messages.json"
    with open(messages_path) as f:
        return json.load(f)
