from dataclasses import asdict, dataclass

import pytest

from aleph.sdk.chains.common import get_verification_buffer
from aleph.sdk.chains.ethereum import verify_signature
from aleph.sdk.exceptions import BadSignatureError
from aleph.sdk.wallets.ledger.ethereum import LedgerETHAccount, get_fallback_account


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


@pytest.mark.ledger_hardware
@pytest.mark.asyncio
async def test_ledger_eth_account():
    account: LedgerETHAccount = get_fallback_account()

    address = account.get_address()
    assert address
    assert type(address) is str
    assert len(address) == 42

    message = Message("ETH", account.get_address(), "SomeType", "ItemHash")
    signed = await account.sign_message(asdict(message))
    assert signed["signature"]
    assert len(signed["signature"]) == 132

    verify_signature(
        signed["signature"], signed["sender"], get_verification_buffer(signed)
    )

    with pytest.raises(BadSignatureError):
        signed["signature"] = signed["signature"][:-8] + "cafecafe"

        verify_signature(
            signed["signature"], signed["sender"], get_verification_buffer(signed)
        )

    # Obtaining the public key is not supported (yet ?) on hardware wallets.
    with pytest.raises(NotImplementedError):
        account.get_public_key()
