# An interface for all clients to implement.

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    AsyncIterable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    Union,
)

from aleph_message.models import (
    AlephMessage,
    MessagesResponse,
    MessageType,
    PostMessage,
)
from aleph_message.models.execution.program import Encoding
from aleph_message.status import MessageStatus

from aleph.sdk.models import PostsResponse
from aleph.sdk.types import GenericMessage, StorageEnum

DEFAULT_PAGE_SIZE = 200


class BaseAlephClient(ABC):
    @abstractmethod
    async def fetch_aggregate(
        self,
        address: str,
        key: str,
        limit: int = 100,
    ) -> Dict[str, Dict]:
        """
        Fetch a value from the aggregate store by owner address and item key.

        :param address: Address of the owner of the aggregate
        :param key: Key of the aggregate
        :param limit: Maximum number of items to fetch (Default: 100)
        """
        pass

    @abstractmethod
    async def fetch_aggregates(
        self,
        address: str,
        keys: Optional[Iterable[str]] = None,
        limit: int = 100,
    ) -> Dict[str, Dict]:
        """
        Fetch key-value pairs from the aggregate store by owner address.

        :param address: Address of the owner of the aggregate
        :param keys: Keys of the aggregates to fetch (Default: all items)
        :param limit: Maximum number of items to fetch (Default: 100)
        """
        pass

    @abstractmethod
    async def get_posts(
        self,
        pagination: int = DEFAULT_PAGE_SIZE,
        page: int = 1,
        types: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ) -> PostsResponse:
        """
        Fetch a list of posts from the network.

        :param pagination: Number of items to fetch (Default: 200)
        :param page: Page to fetch, begins at 1 (Default: 1)
        :param types: Types of posts to fetch (Default: all types)
        :param refs: If set, only fetch posts that reference these hashes (in the "refs" field)
        :param addresses: Addresses of the posts to fetch (Default: all addresses)
        :param tags: Tags of the posts to fetch (Default: all tags)
        :param hashes: Specific item_hashes to fetch
        :param channels: Channels of the posts to fetch (Default: all channels)
        :param chains: Chains of the posts to fetch (Default: all chains)
        :param start_date: Earliest date to fetch messages from
        :param end_date: Latest date to fetch messages from
        :param ignore_invalid_messages: Ignore invalid messages (Default: True)
        :param invalid_messages_log_level: Log level to use for invalid messages (Default: logging.NOTSET)
        """
        pass

    async def get_posts_iterator(
        self,
        types: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
    ) -> AsyncIterable[PostMessage]:
        """
        Fetch all filtered posts, returning an async iterator and fetching them page by page. Might return duplicates
        but will always return all posts.

        :param types: Types of posts to fetch (Default: all types)
        :param refs: If set, only fetch posts that reference these hashes (in the "refs" field)
        :param addresses: Addresses of the posts to fetch (Default: all addresses)
        :param tags: Tags of the posts to fetch (Default: all tags)
        :param hashes: Specific item_hashes to fetch
        :param channels: Channels of the posts to fetch (Default: all channels)
        :param chains: Chains of the posts to fetch (Default: all chains)
        :param start_date: Earliest date to fetch messages from
        :param end_date: Latest date to fetch messages from
        """
        page = 1
        resp = None
        while resp is None or len(resp.posts) > 0:
            resp = await self.get_posts(
                page=page,
                types=types,
                refs=refs,
                addresses=addresses,
                tags=tags,
                hashes=hashes,
                channels=channels,
                chains=chains,
                start_date=start_date,
                end_date=end_date,
            )
            page += 1
            for post in resp.posts:
                yield post

    @abstractmethod
    async def download_file(
        self,
        file_hash: str,
    ) -> bytes:
        """
        Get a file from the storage engine as raw bytes.

        Warning: Downloading large files can be slow and memory intensive.

        :param file_hash: The hash of the file to retrieve.
        """
        pass

    @abstractmethod
    async def get_messages(
        self,
        pagination: int = DEFAULT_PAGE_SIZE,
        page: int = 1,
        message_type: Optional[MessageType] = None,
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
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ) -> MessagesResponse:
        """
        Fetch a list of messages from the network.

        :param pagination: Number of items to fetch (Default: 200)
        :param page: Page to fetch, begins at 1 (Default: 1)
        :param message_type: [DEPRECATED] Filter by message type, can be "AGGREGATE", "POST", "PROGRAM", "VM", "STORE" or "FORGET"
        :param message_types: Filter by message types, can be any combination of "AGGREGATE", "POST", "PROGRAM", "VM", "STORE" or "FORGET"
        :param content_types: Filter by content type
        :param content_keys: Filter by aggregate key
        :param refs: If set, only fetch posts that reference these hashes (in the "refs" field)
        :param addresses: Addresses of the posts to fetch (Default: all addresses)
        :param tags: Tags of the posts to fetch (Default: all tags)
        :param hashes: Specific item_hashes to fetch
        :param channels: Channels of the posts to fetch (Default: all channels)
        :param chains: Filter by sender address chain
        :param start_date: Earliest date to fetch messages from
        :param end_date: Latest date to fetch messages from
        :param ignore_invalid_messages: Ignore invalid messages (Default: True)
        :param invalid_messages_log_level: Log level to use for invalid messages (Default: logging.NOTSET)
        """
        pass

    async def get_messages_iterator(
        self,
        message_type: Optional[MessageType] = None,
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
    ) -> AsyncIterable[AlephMessage]:
        """
        Fetch all filtered messages, returning an async iterator and fetching them page by page. Might return duplicates
        but will always return all messages.

        :param message_type: Filter by message type, can be "AGGREGATE", "POST", "PROGRAM", "VM", "STORE" or "FORGET"
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
        page = 1
        resp = None
        while resp is None or len(resp.messages) > 0:
            resp = await self.get_messages(
                page=page,
                message_type=message_type,
                content_types=content_types,
                content_keys=content_keys,
                refs=refs,
                addresses=addresses,
                tags=tags,
                hashes=hashes,
                channels=channels,
                chains=chains,
                start_date=start_date,
                end_date=end_date,
            )
            page += 1
            for message in resp.messages:
                yield message

    @abstractmethod
    async def get_message(
        self,
        item_hash: str,
        message_type: Optional[Type[GenericMessage]] = None,
        channel: Optional[str] = None,
    ) -> GenericMessage:
        """
        Get a single message from its `item_hash` and perform some basic validation.

        :param item_hash: Hash of the message to fetch
        :param message_type: Type of message to fetch
        :param channel: Channel of the message to fetch
        """
        pass

    @abstractmethod
    def watch_messages(
        self,
        message_type: Optional[MessageType] = None,
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
    ) -> AsyncIterable[AlephMessage]:
        """
        Iterate over current and future matching messages asynchronously.

        :param message_type: [DEPRECATED] Type of message to watch
        :param message_types: Types of messages to watch
        :param content_types: Content types to watch
        :param content_keys: Filter by aggregate key
        :param refs: References to watch
        :param addresses: Addresses to watch
        :param tags: Tags to watch
        :param hashes: Hashes to watch
        :param channels: Channels to watch
        :param chains: Chains to watch
        :param start_date: Start date from when to watch
        :param end_date: End date until when to watch
        """
        pass


class BaseAuthenticatedAlephClient(BaseAlephClient):
    @abstractmethod
    async def create_post(
        self,
        post_content: Any,
        post_type: str,
        ref: Optional[str] = None,
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        storage_engine: StorageEnum = StorageEnum.storage,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Create a POST message on the Aleph network. It is associated with a channel and owned by an account.

        :param post_content: The content of the message
        :param post_type: An arbitrary content type that helps to describe the post_content
        :param ref: A reference to a previous message that it replaces
        :param address: The address that will be displayed as the author of the message
        :param channel: The channel that the message will be posted on
        :param inline: An optional flag to indicate if the content should be inlined in the message or not
        :param storage_engine: An optional storage engine to use for the message, if not inlined (Default: "storage")
        :param sync: If true, waits for the message to be processed by the API server (Default: False)
        """
        pass

    @abstractmethod
    async def create_aggregate(
        self,
        key: str,
        content: Mapping[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Create an AGGREGATE message. It is meant to be used as a quick access storage associated with an account.

        :param key: Key to use to store the content
        :param content: Content to store
        :param address: Address to use to sign the message
        :param channel: Channel to use (Default: "TEST")
        :param inline: Whether to write content inside the message (Default: True)
        :param sync: If true, waits for the message to be processed by the API server (Default: False)
        """
        pass

    @abstractmethod
    async def create_store(
        self,
        address: Optional[str] = None,
        file_content: Optional[bytes] = None,
        file_path: Optional[Union[str, Path]] = None,
        file_hash: Optional[str] = None,
        guess_mime_type: bool = False,
        ref: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        extra_fields: Optional[dict] = None,
        channel: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Create a STORE message to store a file on the Aleph network.

        Can be passed either a file path, an IPFS hash or the file's content as raw bytes.

        :param address: Address to display as the author of the message (Default: account.get_address())
        :param file_content: Byte stream of the file to store (Default: None)
        :param file_path: Path to the file to store (Default: None)
        :param file_hash: Hash of the file to store (Default: None)
        :param guess_mime_type: Guess the MIME type of the file (Default: False)
        :param ref: Reference to a previous message (Default: None)
        :param storage_engine: Storage engine to use (Default: "storage")
        :param extra_fields: Extra fields to add to the STORE message (Default: None)
        :param channel: Channel to post the message to (Default: "TEST")
        :param sync: If true, waits for the message to be processed by the API server (Default: False)
        """
        pass

    @abstractmethod
    async def create_program(
        self,
        program_ref: str,
        entrypoint: str,
        runtime: str,
        environment_variables: Optional[Mapping[str, str]] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
        memory: Optional[int] = None,
        vcpus: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        persistent: bool = False,
        encoding: Encoding = Encoding.zip,
        volumes: Optional[List[Mapping]] = None,
        subscriptions: Optional[List[Mapping]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Post a (create) PROGRAM message.

        :param program_ref: Reference to the program to run
        :param entrypoint: Entrypoint to run
        :param runtime: Runtime to use
        :param environment_variables: Environment variables to pass to the program
        :param storage_engine: Storage engine to use (Default: "storage")
        :param channel: Channel to use (Default: "TEST")
        :param address: Address to use (Default: account.get_address())
        :param sync: If true, waits for the message to be processed by the API server
        :param memory: Memory in MB for the VM to be allocated (Default: 128)
        :param vcpus: Number of vCPUs to allocate (Default: 1)
        :param timeout_seconds: Timeout in seconds (Default: 30.0)
        :param persistent: Whether the program should be persistent or not (Default: False)
        :param encoding: Encoding to use (Default: Encoding.zip)
        :param volumes: Volumes to mount
        :param subscriptions: Patterns of Aleph messages to forward to the program's event receiver
        :param metadata: Metadata to attach to the message
        """
        pass

    @abstractmethod
    async def forget(
        self,
        hashes: List[str],
        reason: Optional[str],
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Post a FORGET message to remove previous messages from the network.

        Targeted messages need to be signed by the same account that is attempting to forget them,
        if the creating address did not delegate the access rights to the forgetting account.

        :param hashes: Hashes of the messages to forget
        :param reason: Reason for forgetting the messages
        :param storage_engine: Storage engine to use (Default: "storage")
        :param channel: Channel to use (Default: "TEST")
        :param address: Address to use (Default: account.get_address())
        :param sync: If true, waits for the message to be processed by the API server (Default: False)
        """
        pass

    @abstractmethod
    async def submit(
        self,
        content: Dict[str, Any],
        message_type: MessageType,
        channel: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        allow_inlining: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Submit a message to the network. This is a generic method that can be used to submit any type of message.
        Prefer using the more specific methods to submit messages.

        :param content: Content of the message
        :param message_type: Type of the message
        :param channel: Channel to use (Default: "TEST")
        :param storage_engine: Storage engine to use (Default: "storage")
        :param allow_inlining: Whether to allow inlining the content of the message (Default: True)
        :param sync: If true, waits for the message to be processed by the API server (Default: False)
        """
        pass
