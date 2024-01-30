import pytest

from aleph.sdk import __version__


def test_version():
    assert __version__ != ""


def test_deprecation():
    with pytest.raises(ImportError):
        from aleph.sdk import AlephClient

    with pytest.raises(ImportError):
        from aleph.sdk import AuthenticatedAlephClient

    with pytest.raises(ImportError):
        from aleph.sdk import synchronous

    with pytest.raises(ImportError):
        from aleph.sdk import asynchronous

    from aleph.sdk import AlephHttpClient