from aleph_message.models import MessagesResponse, MessageType

from aleph.sdk.client import AlephClient
from aleph.sdk.conf import settings
from aleph.sdk.models.message import MessageFilter


def test_get_post_messages():
    with AlephClient(api_server=settings.API_HOST) as session:
        response: MessagesResponse = session.get_messages(
            pagination=2,
            message_filter=MessageFilter(
                message_types=[MessageType.post],
            ),
        )

        messages = response.messages
        assert len(messages) > 1
        for message in messages:
            assert message.type == MessageType.post
