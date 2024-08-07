# An interface for all clients to implement.
import json
import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import (
    Any,
    AsyncIterable,
    Coroutine,
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
    ItemHash,
    ItemType,
    MessagesResponse,
    MessageType,
    Payment,
    PostMessage,
    parse_message,
)
from aleph_message.models.execution.environment import (
    HostRequirements,
    HypervisorType,
    TrustedExecutionEnvironment,
)
from aleph_message.models.execution.program import Encoding
from aleph_message.status import MessageStatus

from aleph.sdk.conf import settings
from aleph.sdk.types import Account
from aleph.sdk.utils import extended_json_encoder

from ..query.filters import MessageFilter, PostFilter
from ..query.responses import PostsResponse, PriceResponse
from ..types import GenericMessage, StorageEnum
from ..utils import Writable, compute_sha256

DEFAULT_PAGE_SIZE = 200


class AlephClient(ABC):
    @abstractmethod
    async def fetch_aggregate(self, address: str, key: str) -> Dict[str, Dict]:
        """
        Fetch a value from the aggregate store by owner address and item key.

        :param address: Address of the owner of the aggregate
        :param key: Key of the aggregate
        """
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")

    @abstractmethod
    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None
    ) -> Dict[str, Dict]:
        """
        Fetch key-value pairs from the aggregate store by owner address.

        :param address: Address of the owner of the aggregate
        :param keys: Keys of the aggregates to fetch (Default: all items)
        """
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")

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
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")

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
    async def download_file(self, file_hash: str) -> bytes:
        """
        Get a file from the storage engine as raw bytes.

        Warning: Downloading large files can be slow and memory intensive. Use `download_file_to()` to download them directly to disk instead.

        :param file_hash: The hash of the file to retrieve.
        """
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")

    @abstractmethod
    async def download_file_to_path(
        self,
        file_hash: str,
        path: Union[Path, str],
    ) -> Path:
        """
        Download a file from the storage engine to given path.

        :param file_hash: The hash of the file to retrieve.
        :param path: The path to which the file should be saved.
        """
        raise NotImplementedError()

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
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")

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
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")

    @abstractmethod
    def watch_messages(
        self,
        message_filter: Optional[MessageFilter] = None,
    ) -> AsyncIterable[AlephMessage]:
        """
        Iterate over current and future matching messages asynchronously.

        :param message_filter: Filter to apply to the messages
        """
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")

    @abstractmethod
    def get_program_price(
        self,
        item_hash: str,
    ) -> Coroutine[Any, Any, PriceResponse]:
        """
        Get Program message Price

        :param item_hash: item_hash of executable message
        """
        raise NotImplementedError("Did you mean to import `AlephHttpClient`?")


class AuthenticatedAlephClient(AlephClient):
    account: Account

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
        raise NotImplementedError(
            "Did you mean to import `AuthenticatedAlephHttpClient`?"
        )

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
        raise NotImplementedError(
            "Did you mean to import `AuthenticatedAlephHttpClient`?"
        )

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
        raise NotImplementedError(
            "Did you mean to import `AuthenticatedAlephHttpClient`?"
        )

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
        raise NotImplementedError(
            "Did you mean to import `AuthenticatedAlephHttpClient`?"
        )

    @abstractmethod
    async def create_instance(
        self,
        rootfs: str,
        rootfs_size: int,
        payment: Optional[Payment] = None,
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
        hypervisor: Optional[HypervisorType] = None,
        trusted_execution: Optional[TrustedExecutionEnvironment] = None,
        volumes: Optional[List[Mapping]] = None,
        volume_persistence: str = "host",
        ssh_keys: Optional[List[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        requirements: Optional[HostRequirements] = None,
    ) -> Tuple[AlephMessage, MessageStatus]:
        """
        Post a (create) INSTANCE message.

        :param rootfs: Root filesystem to use
        :param rootfs_size: Size of root filesystem
        :param payment: Payment method used to pay for the instance
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
        :param hypervisor: Whether the VM should use as Hypervisor, like QEmu or Firecracker (Default: Qemu)
        :param trusted_execution: Whether the VM configuration (firmware and policy) to use for Confidential computing (Default: None)
        :param encoding: Encoding to use (Default: Encoding.zip)
        :param volumes: Volumes to mount
        :param volume_persistence: Where volumes are persisted, can be "host" or "store", meaning distributed across Aleph.im (Default: "host")
        :param ssh_keys: SSH keys to authorize access to the VM
        :param metadata: Metadata to attach to the message
        :param requirements: CRN Requirements needed for the VM execution
        """
        raise NotImplementedError(
            "Did you mean to import `AuthenticatedAlephHttpClient`?"
        )

    @abstractmethod
    async def forget(
        self,
        hashes: List[ItemHash],
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
        raise NotImplementedError(
            "Did you mean to import `AuthenticatedAlephHttpClient`?"
        )

    async def generate_signed_message(
        self,
        message_type: MessageType,
        content: Dict[str, Any],
        channel: Optional[str],
        allow_inlining: bool = True,
        storage_engine: StorageEnum = StorageEnum.storage,
    ) -> AlephMessage:
        """Generate a signed aleph.im message ready to be sent to the network.

        If the content is not inlined, it will be pushed to the storage engine via the API of a Core Channel Node.

        :param message_type: Type of the message (PostMessage, ...)
        :param content: User-defined content of the message
        :param channel: Channel to use (Default: "TEST")
        :param allow_inlining: Whether to allow inlining the content of the message (Default: True)
        :param storage_engine: Storage engine to use (Default: "storage")
        """

        message_dict: Dict[str, Any] = {
            "sender": self.account.get_address(),
            "chain": self.account.CHAIN,
            "type": message_type,
            "content": content,
            "time": time.time(),
            "channel": channel,
        }

        # Use the Pydantic encoder to serialize types like UUID, datetimes, etc.
        item_content: str = json.dumps(
            content, separators=(",", ":"), default=extended_json_encoder
        )

        if allow_inlining and (len(item_content) < settings.MAX_INLINE_SIZE):
            message_dict["item_content"] = item_content
            message_dict["item_hash"] = compute_sha256(item_content)
            message_dict["item_type"] = ItemType.inline
        else:
            if storage_engine == StorageEnum.ipfs:
                message_dict["item_hash"] = await self.ipfs_push(
                    content=content,
                )
                message_dict["item_type"] = ItemType.ipfs
            else:  # storage
                assert storage_engine == StorageEnum.storage
                message_dict["item_hash"] = await self.storage_push(
                    content=content,
                )
                message_dict["item_type"] = ItemType.storage

        message_dict = await self.account.sign_message(message_dict)
        return parse_message(message_dict)

    # Alias for backwards compatibility
    _prepare_aleph_message = generate_signed_message

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
        raise NotImplementedError(
            "Did you mean to import `AuthenticatedAlephHttpClient`?"
        )

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
