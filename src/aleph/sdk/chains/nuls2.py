import base64
from typing import Dict, Union

from nuls2.model.data import (
    NETWORKS,
    address_from_hash,
    public_key_to_hash,
    sign_recoverable_message,
)

from .common import (
    BaseAccount,
    get_fallback_private_key,
    get_public_key,
    get_verification_buffer,
)


def get_address(public_key=None, private_key=None, chain_id=1, prefix="NULS"):
    if public_key is None:
        public_key = get_public_key(private_key=private_key)

    return address_from_hash(
        public_key_to_hash(public_key, chain_id=chain_id), prefix=prefix
    )


class NULSAccount(BaseAccount):
    CHAIN = "NULS2"
    CURVE = "secp256k1"

    def __init__(self, private_key=None, chain_id=1, prefix=None):
        self.private_key = private_key
        self.chain_id = chain_id
        if prefix is None:
            self.prefix = NETWORKS[chain_id]
        else:
            self.prefix = prefix

    async def sign_message(self, message: Dict) -> Dict:
        """
        Returns a signed message from an aleph.im message.
        Args:
            message: Message to sign
        Returns:
            Dict: Signed message
        """
        message = self._setup_sender(message)
        signature = await self.sign_raw(get_verification_buffer(message))
        message["signature"] = signature.decode()
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        sig = sign_recoverable_message(self.private_key, buffer)
        return base64.b64encode(sig)

    def get_address(self):
        return address_from_hash(
            public_key_to_hash(self.get_public_key(), chain_id=self.chain_id),
            prefix=self.prefix,
        )

    def get_public_key(self):
        return get_public_key(private_key=self.private_key)


def get_fallback_account(chain_id=1):
    acc = NULSAccount(private_key=get_fallback_private_key(), chain_id=chain_id)
    return acc


def verify_signature(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
) -> bool:
    """TODO: Implement this"""
    raise NotImplementedError("Not implemented yet")
