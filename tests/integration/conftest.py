import asyncio

import pytest

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount


@pytest.fixture
def fixture_account():
    private_key = get_fallback_private_key()
    return ETHAccount(private_key)


# Fixes the "Event loop is closed" error that happens when running several tests in a row
@pytest.fixture(scope="session")
def event_loop(request):
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
