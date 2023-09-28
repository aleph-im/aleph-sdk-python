from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from aleph_message import parse_message
from aleph_message.models import AlephMessage, MessageType
from playhouse.shortcuts import model_to_dict

from .common import (
    PaginationResponse,
    _date_field_to_float,
    query_db_field,
    serialize_list,
)
from .db.message import MessageDBModel


class MessagesResponse(PaginationResponse):
    """Response from an Aleph node API on the path /api/v0/messages.json"""

    messages: List[AlephMessage]
    pagination_item = "messages"


class MessageFilter:
    """
    A collection of filters that can be applied on message queries.
    :param message_types: Filter by message type
    :param content_types: Filter by content type
    :param content_keys: Filter by content key
    :param refs: If set, only fetch posts that reference these hashes (in the "refs" field)
    :param addresses: Addresses of the posts to fetch (Default: all addresses)
    :param tags: Tags of the posts to fetch (Default: all tags)
    :param hashes: Specific item_hashes to fetch
    :param channels: Channels of the posts to fetch (Default: all channels)
    :param chains: Filter by sender address chain
    :param start_date: Earliest date to fetch messages from
    :param end_date: Latest date to fetch messages from
    """

    message_types: Optional[Iterable[MessageType]]
    content_types: Optional[Iterable[str]]
    content_keys: Optional[Iterable[str]]
    refs: Optional[Iterable[str]]
    addresses: Optional[Iterable[str]]
    tags: Optional[Iterable[str]]
    hashes: Optional[Iterable[str]]
    channels: Optional[Iterable[str]]
    chains: Optional[Iterable[str]]
    start_date: Optional[Union[datetime, float]]
    end_date: Optional[Union[datetime, float]]

    def __init__(
        self,
        message_types: Optional[Iterable[MessageType]] = None,
        content_types: Optional[Iterable[str]] = None,
        content_keys: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
    ):
        self.message_types = message_types
        self.content_types = content_types
        self.content_keys = content_keys
        self.refs = refs
        self.addresses = addresses
        self.tags = tags
        self.hashes = hashes
        self.channels = channels
        self.chains = chains
        self.start_date = start_date
        self.end_date = end_date

    def as_http_params(self) -> Dict[str, str]:
        """Convert the filters into a dict that can be used by an `aiohttp` client
        as `params` to build the HTTP query string.
        """

        partial_result = {
            "msgType": serialize_list(
                [type.value for type in self.message_types]
                if self.message_types
                else None
            ),
            "contentTypes": serialize_list(self.content_types),
            "contentKeys": serialize_list(self.content_keys),
            "refs": serialize_list(self.refs),
            "addresses": serialize_list(self.addresses),
            "tags": serialize_list(self.tags),
            "hashes": serialize_list(self.hashes),
            "channels": serialize_list(self.channels),
            "chains": serialize_list(self.chains),
            "startDate": _date_field_to_float(self.start_date),
            "endDate": _date_field_to_float(self.end_date),
        }

        # Ensure all values are strings.
        result: Dict[str, str] = {}

        # Drop empty values
        for key, value in partial_result.items():
            if value:
                assert isinstance(value, str), f"Value must be a string: `{value}`"
                result[key] = value

        return result

    def as_db_query(self):
        query = MessageDBModel.select().order_by(MessageDBModel.time.desc())
        conditions = []
        if self.message_types:
            conditions.append(
                query_db_field(
                    MessageDBModel, "type", [type.value for type in self.message_types]
                )
            )
        if self.content_keys:
            conditions.append(query_db_field(MessageDBModel, "key", self.content_keys))
        if self.content_types:
            conditions.append(
                query_db_field(MessageDBModel, "content_type", self.content_types)
            )
        if self.refs:
            conditions.append(query_db_field(MessageDBModel, "ref", self.refs))
        if self.addresses:
            conditions.append(query_db_field(MessageDBModel, "sender", self.addresses))
        if self.tags:
            for tag in self.tags:
                conditions.append(MessageDBModel.tags.contains(tag))
        if self.hashes:
            conditions.append(query_db_field(MessageDBModel, "item_hash", self.hashes))
        if self.channels:
            conditions.append(query_db_field(MessageDBModel, "channel", self.channels))
        if self.chains:
            conditions.append(query_db_field(MessageDBModel, "chain", self.chains))
        if self.start_date:
            conditions.append(MessageDBModel.time >= self.start_date)
        if self.end_date:
            conditions.append(MessageDBModel.time <= self.end_date)

        if conditions:
            query = query.where(*conditions)
        return query


def message_to_model(message: AlephMessage) -> Dict:
    return {
        "item_hash": str(message.item_hash),
        "chain": message.chain,
        "type": message.type,
        "sender": message.sender,
        "channel": message.channel,
        "confirmations": message.confirmations[0] if message.confirmations else None,
        "confirmed": message.confirmed,
        "signature": message.signature,
        "size": message.size,
        "time": message.time,
        "item_type": message.item_type,
        "item_content": message.item_content,
        "hash_type": message.hash_type,
        "content": message.content,
        "forgotten_by": message.forgotten_by[0] if message.forgotten_by else None,
        "tags": message.content.content.get("tags", None)
        if hasattr(message.content, "content")
        else None,
        "key": message.content.key if hasattr(message.content, "key") else None,
        "ref": message.content.ref if hasattr(message.content, "ref") else None,
        "content_type": message.content.type
        if hasattr(message.content, "type")
        else None,
    }


def model_to_message(item: Any) -> AlephMessage:
    item.confirmations = [item.confirmations] if item.confirmations else []
    item.forgotten_by = [item.forgotten_by] if item.forgotten_by else None

    to_exclude = [
        MessageDBModel.tags,
        MessageDBModel.ref,
        MessageDBModel.key,
        MessageDBModel.content_type,
    ]

    item_dict = model_to_dict(item, exclude=to_exclude)
    return parse_message(item_dict)
