"""The NULS1 implementation switched from lib `secp256k1` to `coincurve`.

This file tests that both implementations returns identical results.
"""

from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
import secp256k1
from coincurve.keys import PrivateKey

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.nuls1 import LOGGER, MESSAGE_TEMPLATE, NulsSignature, VarInt

SECRET = (
    b"\xc4\xfe\xe65\x96\x14\xb4:\r: \x05;\x12j\x9bJ"
    b"\x14\x0eY\xe3BY\x0f\xd6\xee\xfc\x9d\xfe\x8fv\xbc"
)


class NulsSignatureSecp256k1(NulsSignature):
    @classmethod
    def sign_data_deprecated(cls, pri_key: bytes, digest_bytes: bytes):
        # TODO: Test compatibility and remove
        privkey = secp256k1.PrivateKey(
            pri_key, raw=True
        )  # we expect to have a private key as bytes. unhexlify it before passing.
        item = cls()
        item.pub_key = privkey.pubkey.serialize()
        item.digest_bytes = digest_bytes
        sig_check = privkey.ecdsa_sign(digest_bytes, raw=True)
        print("sig_check", sig_check)
        item.sig_ser = privkey.ecdsa_serialize(sig_check)
        return item

    @classmethod
    def sign_message_deprecated(cls, pri_key: bytes, message):
        # TODO: Test compatibility and remove
        # we expect to have a private key as bytes. unhexlify it before passing
        privkey = secp256k1.PrivateKey(pri_key, raw=True)
        item = cls()
        message = VarInt(len(message)).encode() + message
        item.pub_key = privkey.pubkey.serialize()
        # item.digest_bytes = digest_bytes
        sig_check = privkey.ecdsa_sign(MESSAGE_TEMPLATE.format(message).encode())
        item.sig_ser = privkey.ecdsa_serialize(sig_check)
        return item

    def verify_deprecated(self, message):
        pub = secp256k1.PublicKey(self.pub_key, raw=True)
        message = VarInt(len(message)).encode() + message
        print("message", message)
        # LOGGER.debug("Comparing with %r" % (MESSAGE_TEMPLATE.format(message).encode()))
        try:
            sig_raw = pub.ecdsa_deserialize(self.sig_ser)
            good = pub.ecdsa_verify(MESSAGE_TEMPLATE.format(message).encode(), sig_raw)
        except Exception:
            LOGGER.exception("Verification failed")
            good = False
        return good


def test_sign_data_deprecated():
    """Test the data signature"""
    data = None
    signature = NulsSignature(data=data)

    with NamedTemporaryFile() as private_key_file:
        private_key = get_fallback_private_key(path=Path(private_key_file.name))

        assert signature
        sign_deprecated: NulsSignatureSecp256k1 = (
            NulsSignatureSecp256k1.sign_data_deprecated(
                pri_key=private_key, digest_bytes=b"x" * (256 // 8)
            )
        )
        assert sign_deprecated


@pytest.mark.asyncio
async def test_compare_sign_data():
    private_key = PrivateKey(SECRET)

    sign: NulsSignature = NulsSignature.sign_data(
        pri_key=private_key.secret, digest_bytes=b"x" * (256 // 8)
    )

    sign_deprecated: NulsSignatureSecp256k1 = (
        NulsSignatureSecp256k1.sign_data_deprecated(
            pri_key=private_key.secret, digest_bytes=b"x" * (256 // 8)
        )
    )

    assert sign.sig_ser is not None
    assert sign_deprecated.sig_ser is not None
    assert len(sign.sig_ser) == len(sign_deprecated.sig_ser)
    assert sign.sig_ser == sign_deprecated.sig_ser
    assert sign == sign_deprecated


@pytest.mark.asyncio
async def test_compare_sign_message():
    private_key = PrivateKey(SECRET)
    message = b"GOOD"

    sign: NulsSignature = await NulsSignature.sign_message(
        pri_key=private_key.secret, message=message
    )

    sign_deprecated: NulsSignatureSecp256k1 = (
        NulsSignatureSecp256k1.sign_message_deprecated(
            pri_key=private_key.secret, message=message
        )
    )

    assert sign.sig_ser is not None
    assert sign_deprecated.sig_ser is not None
    assert len(sign.sig_ser) == len(sign_deprecated.sig_ser)
    assert sign.sig_ser == sign_deprecated.sig_ser
    assert sign == sign_deprecated


@pytest.mark.asyncio
async def test_verify():
    private_key = PrivateKey(SECRET)
    message = b"GOOD"

    sign: NulsSignatureSecp256k1 = await NulsSignatureSecp256k1.sign_message(
        pri_key=private_key.secret, message=message
    )

    assert sign.verify(message=message)
    assert not sign.verify(message=b"BAD")

    assert sign.verify_deprecated(message=message)
    assert not sign.verify_deprecated(message=b"BAD")
