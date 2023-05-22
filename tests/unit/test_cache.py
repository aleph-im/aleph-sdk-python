from src.aleph.sdk.cache import MessageCache
from src.aleph.sdk.client import AlephClient, UserSessionSync
from src.aleph.sdk.conf import settings


def test_message_cache():
    session = UserSessionSync(AlephClient(settings.API_HOST))
    messages = session.get_messages().messages

    # test add_many
    cache = MessageCache()
    cache.add_many(messages)

    # test get_many
    item_hashes = [message.item_hash for message in messages]
    cached_messages = cache.get_many(item_hashes)
    assert len(cached_messages) == len(messages)

    # test __getitem__
    for message in messages:
        assert cache[message.item_hash] == message

    # test __contains__
    for message in messages:
        assert message.item_hash in cache
