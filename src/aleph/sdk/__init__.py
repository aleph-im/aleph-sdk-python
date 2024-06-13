from importlib.metadata import PackageNotFoundError, version

from aleph.sdk.client import AlephHttpClient, AuthenticatedAlephHttpClient

try:
    # Change here if project is renamed and does not equal the package name
    __version__ = version("aleph-sdk-python")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = ["__version__", "AlephHttpClient", "AuthenticatedAlephHttpClient"]


def __getattr__(name):
    if name == "AlephClient":
        raise ImportError(
            "AlephClient has been turned into an abstract class. Please use `AlephHttpClient` instead."
        )
    elif name == "AuthenticatedAlephClient":
        raise ImportError(
            "AuthenticatedAlephClient has been turned into an abstract class. Please use `AuthenticatedAlephHttpClient` instead."
        )
    elif name == "synchronous":
        raise ImportError(
            "The 'aleph.sdk.synchronous' type is deprecated and has been removed from the aleph SDK. Please use `aleph.sdk.client.AlephHttpClient` instead."
        )
    elif name == "asynchronous":
        raise ImportError(
            "The 'aleph.sdk.asynchronous' type is deprecated and has been removed from the aleph SDK. Please use `aleph.sdk.client.AlephHttpClient` instead."
        )
