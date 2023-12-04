# An interface for all clients to implement.

import logging
from abc import ABC, abstractmethod
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

from ..query.filters import MessageFilter, PostFilter
from ..query.responses import PostsResponse
from ..types import GenericMessage, StorageEnum
from ..utils import Writable

DEFAULT_PAGE_SIZE = 200


class AlephClient(ABC):
    @abstractmethod
    async def fetch_aggregate(self, address: str, key: str) -> Dict[str, Dict]:
        """
        Fetch a value from the aggregate store by owner address and item key.

        :param address: Address of the owner of the aggregate
        :param key: Key of the aggregate
        """
        pass

    @abstractmethod
    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None
    ) -> Dict[str, Dict]:
        """
        Fetch key-value pairs from the aggregate store by owner address.

        :param address: Address of the owner of the aggregate
        :param keys: Keys of the aggregates to fetch (Default: all items)
        """
        pass

    @abstractmethod
    async def get_posts(
        self,
        page_size: int = DEFAULT_PAGE_SIZE,
        page: int = 1,
        post_filter: Optional[PostFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> PostsResponse:
        """
        Fetch a list of posts from the network.

        :param page_size: Number of items to fetch (Default: 200)
        :param page: Page to fetch, begins at 1 (Default: 1)
        :param post_filter: Filter to apply to the posts (Default: None)
        :param ignore_invalid_messages: Ignore invalid messages (Default: True)
        :param invalid_messages_log_level: Log level to use for invalid messages (Default: logging.NOTSET)
        """
        pass

    async def get_posts_iterator(
        self,
        post_filter: Optional[PostFilter] = None,
    ) -> AsyncIterable[PostMessage]:
        """
        Fetch all filtered posts, returning an async iterator and fetching them page by page. Might return duplicates
        but will always return all posts.

        :param post_filter: Filter to apply to the posts (Default: None)
        """
        page = 1
        resp = None
        while resp is None or len(resp.posts) > 0:
            resp = await self.get_posts(
                page=page,
                post_filter=post_filter,
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

    async def download_file_ipfs(
        self,
        file_hash: str,
    ) -> bytes:
        """
        Get a file from the ipfs storage engine as raw bytes.

        Warning: Downloading large files can be slow.

        :param file_hash: The hash of the file to retrieve.
        """
        raise NotImplementedError()

    async def download_file_ipfs_to_buffer(
        self,
        file_hash: str,
        output_buffer: Writable[bytes],
    ) -> None:
        """
        Download a file from the storage engine and write it to the specified output buffer.

        :param file_hash: The hash of the file to retrieve.
        :param output_buffer: The binary output buffer to write the file data to.
        """
        raise NotImplementedError()

    async def download_file_to_buffer(
        self,
        file_hash: str,
        output_buffer: Writable[bytes],
    ) -> None:
        """
        Download a file from the storage engine and write it to the specified output buffer.
        :param file_hash: The hash of the file to retrieve.
        :param output_buffer: Writable binary buffer. The file will be written to this buffer.
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_messages(
        self,
        page_size: int = DEFAULT_PAGE_SIZE,
        page: int = 1,
        message_filter: Optional[MessageFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> MessagesResponse:
        """
        Fetch a list of messages from the network.

        :param page_size: Number of items to fetch (Default: 200)
        :param page: Page to fetch, begins at 1 (Default: 1)
        :param message_filter: Filter to apply to the messages
        :param ignore_invalid_messages: Ignore invalid messages (Default: True)
        :param invalid_messages_log_level: Log level to use for invalid messages (Default: logging.NOTSET)
        """
        pass

    async def get_messages_iterator(
        self,
        message_filter: Optional[MessageFilter] = None,
    ) -> AsyncIterable[AlephMessage]:
        """
        Fetch all filtered messages, returning an async iterator and fetching them page by page. Might return duplicates
        but will always return all messages.

        :param message_filter: Filter to apply to the messages
        """
        page = 1
        resp = None
        while resp is None or len(resp.messages) > 0:
            resp = await self.get_messages(
                page=page,
                message_filter=message_filter,
            )
            page += 1
            for message in resp.messages:
                yield message

    @abstractmethod
    async def get_message(
        self,
        item_hash: str,
        message_type: Optional[Type[GenericMessage]] = None,
    ) -> GenericMessage:
        """
        Get a single message from its `item_hash` and perform some basic validation.

        :param item_hash: Hash of the message to fetch
        :param message_type: Type of message to fetch
        """
        pass

    @abstractmethod
    def watch_messages(
        self,
        message_filter: Optional[MessageFilter] = None,
    ) -> AsyncIterable[AlephMessage]:
        """
        Iterate over current and future matching messages asynchronously.

        :param message_filter: Filter to apply to the messages
        """
        pass


class AuthenticatedAlephClient(AlephClient):
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
        Create a POST message on the aleph.im network. It is associated with a channel and owned by an account.

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
        Create a STORE message to store a file on the aleph.im network.

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
        allow_amend: bool = False,
        internet: bool = True,
        aleph_api: bool = True,
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
        :param allow_amend: Whether the deployed VM image may be changed (Default: False)
        :param internet: Whether the VM should have internet connectivity. (Default: True)
        :param aleph_api: Whether the VM needs access to Aleph messages API (Default: True)
        :param encoding: Encoding to use (Default: Encoding.zip)
        :param volumes: Volumes to mount
        :param subscriptions: Patterns of aleph.im messages to forward to the program's event receiver
        :param metadata: Metadata to attach to the message
        """
        pass

    @abstractmethod
    async def create_instance(
        self,
        rootfs: str,
        rootfs_size: int,
        rootfs_name: str,
        environment_variables: Optional[Mapping[str, str]] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
        memory: Optional[int] = None,
        vcpus: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        allow_amend: bool = False,
        internet: bool = True,
        aleph_api: bool = True,
        encoding: Encoding = Encoding.zip,
        volumes: Optional[List[Mapping]] = None,
        volume_persistence: str = "host",
        ssh_keys: Optional[List[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Post a (create) PROGRAM message.

        :param rootfs: Root filesystem to use
        :param rootfs_size: Size of root filesystem
        :param rootfs_name: Name of root filesystem
        :param environment_variables: Environment variables to pass to the program
        :param storage_engine: Storage engine to use (Default: "storage")
        :param channel: Channel to use (Default: "TEST")
        :param address: Address to use (Default: account.get_address())
        :param sync: If true, waits for the message to be processed by the API server
        :param memory: Memory in MB for the VM to be allocated (Default: 128)
        :param vcpus: Number of vCPUs to allocate (Default: 1)
        :param timeout_seconds: Timeout in seconds (Default: 30.0)
        :param allow_amend: Whether the deployed VM image may be changed (Default: False)
        :param internet: Whether the VM should have internet connectivity. (Default: True)
        :param aleph_api: Whether the VM needs access to Aleph messages API (Default: True)
        :param encoding: Encoding to use (Default: Encoding.zip)
        :param volumes: Volumes to mount
        :param volume_persistence: Where volumes are persisted, can be "host" or "store", meaning distributed across Aleph.im (Default: "host")
        :param ssh_keys: SSH keys to authorize access to the VM
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
        raise_on_rejected: bool = True,
    ) -> Tuple[AlephMessage, MessageStatus, Optional[Dict[str, Any]]]:
        """
        Submit a message to the network. This is a generic method that can be used to submit any type of message.
        Prefer using the more specific methods to submit messages.

        :param content: Content of the message
        :param message_type: Type of the message
        :param channel: Channel to use (Default: "TEST")
        :param storage_engine: Storage engine to use (Default: "storage")
        :param allow_inlining: Whether to allow inlining the content of the message (Default: True)
        :param sync: If true, waits for the message to be processed by the API server (Default: False)
        :param raise_on_rejected: Whether to raise an exception if the message is rejected (Default: True)
        """
        pass

    async def ipfs_push(self, content: Mapping) -> str:
        """
        Push a file to IPFS.

        :param content: Content of the file to push
        """
        raise NotImplementedError()

    async def storage_push(self, content: Mapping) -> str:
        """
        Push arbitrary content as JSON to the storage service.

        :param content: The dict-like content to upload
        """
        raise NotImplementedError()
