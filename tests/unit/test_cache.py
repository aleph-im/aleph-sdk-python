from src.aleph.sdk.cache import MessageCache
from src.aleph.sdk.client import AlephClient
from src.aleph.sdk.client import UserSessionSync
from src.aleph.sdk.conf import settings


def test_message_cache():
    session = UserSessionSync(AlephClient(settings.API_HOST))
    cache = MessageCache()
    messages = session.get_messages()
    m = messages.messages[0]
    print(m)
    cache.add(m)
    assert cache.get(m.item_hash) == m
