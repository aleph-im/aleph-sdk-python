import warnings

from aleph.sdk.chains.solana import *  # noqa

warnings.warn(
    "aleph.sdk.chains.sol is deprecated, use aleph.sdk.chains.solana instead",
    DeprecationWarning,
    stacklevel=1,
)
