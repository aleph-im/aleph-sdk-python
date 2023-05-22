from aleph_message.models import Chain, ItemType

from aleph.sdk.chains.common import get_verification_buffer


def test_get_verification_buffer():
    message = {
        "chain": Chain.ETH,
        "sender": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "type": ItemType.inline,
        "item_hash": "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4",
    }
    assert get_verification_buffer(message) == (
        b"ETH\n"
        b"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9\n"
        b"inline\n"
        b"bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
    )
