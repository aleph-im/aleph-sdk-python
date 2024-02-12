import pytest

from aleph.sdk import __version__


def test_version():
    assert __version__ != ""


def test_deprecation():
    with pytest.raises(ImportError):
        from aleph.sdk import AlephClient  # noqa

    with pytest.raises(ImportError):
        from aleph.sdk import AuthenticatedAlephClient  # noqa

    with pytest.raises(ImportError):
        from aleph.sdk import synchronous  # noqa

    with pytest.raises(ImportError):
        from aleph.sdk import asynchronous  # noqa

    with pytest.raises(ImportError):
        import aleph.sdk.synchronous  # noqa

    with pytest.raises(ImportError):
        import aleph.sdk.asynchronous  # noqa

    from aleph.sdk import AlephHttpClient  # noqa
