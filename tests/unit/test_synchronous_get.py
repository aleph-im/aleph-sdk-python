from aleph_message.models import MessagesResponse, MessageType

from aleph.sdk.client import AlephClient
from aleph.sdk.conf import settings


def test_get_posts():
    with AlephClient(api_server=settings.API_HOST) as session:
        response: MessagesResponse = session.get_messages(
            pagination=2,
            message_type=MessageType.post,
        )

        messages = response.messages
        assert len(messages) > 1
        for message in messages:
            assert message.type == MessageType.post
