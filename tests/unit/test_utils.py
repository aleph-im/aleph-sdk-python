from aleph_message.models import (
    AggregateMessage,
    Chain,
    ForgetMessage,
    ItemType,
    MessageType,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)

from aleph.sdk.utils import enum_as_str, get_message_type_value


def test_get_message_type_value():
    assert get_message_type_value(PostMessage) == MessageType.post
    assert get_message_type_value(AggregateMessage) == MessageType.aggregate
    assert get_message_type_value(StoreMessage) == MessageType.store
    assert get_message_type_value(ProgramMessage) == MessageType.program
    assert get_message_type_value(ForgetMessage) == MessageType.forget


def test_enum_as_str():
    assert enum_as_str("simple string") == "simple string"
    assert enum_as_str(Chain("ETH")) == "ETH"
    assert enum_as_str(Chain.ETH) == "ETH"
    assert enum_as_str(ItemType("inline")) == "inline"
    assert enum_as_str(ItemType.inline) == "inline"
