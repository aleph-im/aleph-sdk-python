from typing import Optional

from aleph_message.models import Chain

from .solana import SOLAccount


class SVMAccount(SOLAccount):
    def __init__(self, private_key: bytes, chain: Optional[Chain] = None):
        super().__init__(private_key=private_key)
        # Same as EVM ACCOUNT need to decided if we want to send the specified chain or always use SOL
        if chain:
            self.CHAIN = chain
