import asyncio
import hashlib
import json
import logging
import queue
import threading
import time
from io import BytesIO
from pathlib import Path
from typing import (
    Any,
    AsyncIterable,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    NoReturn,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)

import aiohttp
from aleph_message.models import (
    AggregateContent,
    AggregateMessage,
    AlephMessage,
    ForgetContent,
    ForgetMessage,
    ItemHash,
    ItemType,
    MessageType,
    PostContent,
    PostMessage,
    ProgramContent,
    ProgramMessage,
    StoreContent,
    StoreMessage,
    parse_message,
)
from aleph_message.models.execution.base import Encoding
from aleph_message.status import MessageStatus
from pydantic import ValidationError
from pydantic.json import pydantic_encoder

from aleph.sdk.types import Account, GenericMessage, StorageEnum
from aleph.sdk.utils import Writable, copy_async_readable_to_buffer

from .base import BaseAlephClient, BaseAuthenticatedAlephClient
from .conf import settings
from .exceptions import (
    BroadcastError,
    FileTooLarge,
    InvalidMessageError,
    MessageNotFoundError,
    MultipleMessagesError,
)
from .models.message import MessageFilter, MessagesResponse
from .models.post import Post, PostFilter, PostsResponse
from .utils import check_unix_socket_valid, get_message_type_value

logger = logging.getLogger(__name__)

try:
    import magic
except ImportError:
    logger.info("Could not import library 'magic', MIME type detection disabled")
    magic = None  # type:ignore

T = TypeVar("T")


def async_wrapper(f):
    """
    Copies the docstring of wrapped functions.
    """

    wrapped = getattr(AuthenticatedAlephClient, f.__name__)
    f.__doc__ = wrapped.__doc__


def wrap_async(func: Callable[..., Awaitable[T]]) -> Callable[..., T]:
    """Wrap an asynchronous function into a synchronous one,
    for easy use in synchronous code.
    """

    def func_caller(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(func(*args, **kwargs))

    # Copy wrapped function interface:
    func_caller.__doc__ = func.__doc__
    func_caller.__annotations__ = func.__annotations__
    func_caller.__defaults__ = func.__defaults__
    func_caller.__kwdefaults__ = func.__kwdefaults__
    return func_caller


async def run_async_watcher(
    *args, output_queue: queue.Queue, api_server: Optional[str], **kwargs
):
    async with AlephClient(api_server=api_server) as session:
        async for message in session.watch_messages(*args, **kwargs):
            output_queue.put(message)


def watcher_thread(output_queue: queue.Queue, api_server: Optional[str], args, kwargs):
    asyncio.run(
        run_async_watcher(
            output_queue=output_queue, api_server=api_server, *args, **kwargs
        )
    )


class UserSessionSync:
    """
    A sync version of `UserSession`, used in sync code.

    This class is returned by the context manager of `UserSession` and is
    intended as a wrapper around the methods of `UserSession` and not as a public class.
    The methods are fully typed to enable static type checking, but most (all) methods
    should look like this (using args and kwargs for brevity, but the functions should
    be fully typed):

    >>> def func(self, *args, **kwargs):
    >>>     return self._wrap(self.async_session.func)(*args, **kwargs)
    """

    def __init__(self, async_session: "AlephClient"):
        self.async_session = async_session

    def _wrap(self, method: Callable[..., Awaitable[T]], *args, **kwargs):
        return wrap_async(method)(*args, **kwargs)

    def get_messages(
        self,
        pagination: int = 200,
        page: int = 1,
        message_filter: Optional[MessageFilter] = None,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ) -> MessagesResponse:
        return self._wrap(
            self.async_session.get_messages,
            pagination=pagination,
            page=page,
            message_filter=message_filter,
            ignore_invalid_messages=ignore_invalid_messages,
            invalid_messages_log_level=invalid_messages_log_level,
        )

    # @async_wrapper
    def get_message(
        self,
        item_hash: str,
        message_type: Optional[Type[GenericMessage]] = None,
        channel: Optional[str] = None,
    ) -> GenericMessage:
        return self._wrap(
            self.async_session.get_message,
            item_hash=item_hash,
            message_type=message_type,
            channel=channel,
        )

    def fetch_aggregate(
        self,
        address: str,
        key: str,
        limit: int = 100,
    ) -> Dict[str, Dict]:
        return self._wrap(self.async_session.fetch_aggregate, address, key, limit)

    def fetch_aggregates(
        self,
        address: str,
        keys: Optional[Iterable[str]] = None,
        limit: int = 100,
    ) -> Dict[str, Dict]:
        return self._wrap(self.async_session.fetch_aggregates, address, keys, limit)

    def get_posts(
        self,
        pagination: int = 200,
        page: int = 1,
        post_filter: Optional[PostFilter] = None,
    ) -> PostsResponse:
        return self._wrap(
            self.async_session.get_posts,
            pagination=pagination,
            page=page,
            post_filter=post_filter,
        )

    def download_file(self, file_hash: str) -> bytes:
        return self._wrap(self.async_session.download_file, file_hash=file_hash)

    def download_file_ipfs(self, file_hash: str) -> bytes:
        return self._wrap(
            self.async_session.download_file_ipfs,
            file_hash=file_hash,
        )

    def download_file_to_buffer(
        self, file_hash: str, output_buffer: Writable[bytes]
    ) -> None:
        return self._wrap(
            self.async_session.download_file_to_buffer,
            file_hash=file_hash,
            output_buffer=output_buffer,
        )

    def download_file_ipfs_to_buffer(
        self, file_hash: str, output_buffer: Writable[bytes]
    ) -> None:
        return self._wrap(
            self.async_session.download_file_ipfs_to_buffer,
            file_hash=file_hash,
            output_buffer=output_buffer,
        )

    def watch_messages(
        self,
        message_filter: Optional[MessageFilter] = None,
    ) -> Iterable[AlephMessage]:
        """
        Iterate over current and future matching messages synchronously.

        Runs the `watch_messages` asynchronous generator in a thread.
        """
        output_queue: queue.Queue[AlephMessage] = queue.Queue()
        thread = threading.Thread(
            target=watcher_thread,
            args=(
                output_queue,
                self.async_session.api_server,
                message_filter,
                {},
            ),
        )
        thread.start()
        while True:
            yield output_queue.get()


class AuthenticatedUserSessionSync(UserSessionSync):
    async_session: "AuthenticatedAlephClient"

    def __init__(self, async_session: "AuthenticatedAlephClient"):
        super().__init__(async_session=async_session)

    def ipfs_push(self, content: Mapping) -> str:
        return self._wrap(self.async_session.ipfs_push, content=content)

    def storage_push(self, content: Mapping) -> str:
        return self._wrap(self.async_session.storage_push, content=content)

    def ipfs_push_file(self, file_content: Union[str, bytes]) -> str:
        return self._wrap(self.async_session.ipfs_push_file, file_content=file_content)

    def storage_push_file(self, file_content: Union[str, bytes]) -> str:
        return self._wrap(
            self.async_session.storage_push_file, file_content=file_content
        )

    def create_post(
        self,
        post_content,
        post_type: str,
        ref: Optional[str] = None,
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        storage_engine: StorageEnum = StorageEnum.storage,
        sync: bool = False,
    ) -> Tuple[PostMessage, MessageStatus]:
        return self._wrap(
            self.async_session.create_post,
            post_content=post_content,
            post_type=post_type,
            ref=ref,
            address=address,
            channel=channel,
            inline=inline,
            storage_engine=storage_engine,
            sync=sync,
        )

    def create_aggregate(
        self,
        key: str,
        content: Mapping[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        sync: bool = False,
    ) -> Tuple[AggregateMessage, MessageStatus]:
        return self._wrap(
            self.async_session.create_aggregate,
            key=key,
            content=content,
            address=address,
            channel=channel,
            inline=inline,
            sync=sync,
        )

    def create_store(
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
    ) -> Tuple[StoreMessage, MessageStatus]:
        return self._wrap(
            self.async_session.create_store,
            address=address,
            file_content=file_content,
            file_path=file_path,
            file_hash=file_hash,
            guess_mime_type=guess_mime_type,
            ref=ref,
            storage_engine=storage_engine,
            extra_fields=extra_fields,
            channel=channel,
            sync=sync,
        )

    def create_program(
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
    ) -> Tuple[ProgramMessage, MessageStatus]:
        return self._wrap(
            self.async_session.create_program,
            program_ref=program_ref,
            entrypoint=entrypoint,
            runtime=runtime,
            environment_variables=environment_variables,
            storage_engine=storage_engine,
            channel=channel,
            address=address,
            sync=sync,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            persistent=persistent,
            encoding=encoding,
            volumes=volumes,
            subscriptions=subscriptions,
            metadata=metadata,
        )

    def forget(
        self,
        hashes: List[str],
        reason: Optional[str],
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[ForgetMessage, MessageStatus]:
        return self._wrap(
            self.async_session.forget,
            hashes=hashes,
            reason=reason,
            storage_engine=storage_engine,
            channel=channel,
            address=address,
            sync=sync,
        )

    def submit(
        self,
        content: Dict[str, Any],
        message_type: MessageType,
        channel: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        allow_inlining: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        return self._wrap(
            self.async_session.submit,
            content=content,
            message_type=message_type,
            channel=channel,
            storage_engine=storage_engine,
            allow_inlining=allow_inlining,
            sync=sync,
        )


class AlephClient(BaseAlephClient):
    api_server: str
    http_session: aiohttp.ClientSession

    def __init__(
        self,
        api_server: Optional[str] = None,
        api_unix_socket: Optional[str] = None,
        allow_unix_sockets: bool = True,
        timeout: Optional[aiohttp.ClientTimeout] = None,
    ):
        """AlephClient can use HTTP(S) or HTTP over Unix sockets.
        Unix sockets are used when running inside a virtual machine,
        and can be shared across containers in a more secure way than TCP ports.
        """
        self.api_server = api_server or settings.API_HOST
        if not self.api_server:
            raise ValueError("Missing API host")

        unix_socket_path = api_unix_socket or settings.API_UNIX_SOCKET
        if unix_socket_path and allow_unix_sockets:
            check_unix_socket_valid(unix_socket_path)
            connector = aiohttp.UnixConnector(path=unix_socket_path)
        else:
            connector = None

        # ClientSession timeout defaults to a private sentinel object and may not be None.
        self.http_session = (
            aiohttp.ClientSession(
                base_url=self.api_server, connector=connector, timeout=timeout
            )
            if timeout
            else aiohttp.ClientSession(
                base_url=self.api_server,
                connector=connector,
            )
        )

    def __enter__(self) -> UserSessionSync:
        return UserSessionSync(async_session=self)

    def __exit__(self, exc_type, exc_val, exc_tb):
        close_fut = self.http_session.close()
        try:
            loop = asyncio.get_running_loop()
            loop.run_until_complete(close_fut)
        except RuntimeError:
            asyncio.run(close_fut)

    async def __aenter__(self) -> "AlephClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_session.close()

    async def fetch_aggregate(self, address: str, key: str) -> Dict[str, Dict]:
        params: Dict[str, Any] = {"keys": key}

        async with self.http_session.get(
            f"/api/v0/aggregates/{address}.json", params=params
        ) as resp:
            result = await resp.json()
            data = result.get("data", dict())
            return data.get(key)

    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None
    ) -> Dict[str, Dict]:
        keys_str = ",".join(keys) if keys else ""
        params: Dict[str, Any] = {}
        if keys_str:
            params["keys"] = keys_str

        async with self.http_session.get(
            f"/api/v0/aggregates/{address}.json",
            params=params,
        ) as resp:
            result = await resp.json()
            data = result.get("data", dict())
            return data

    async def get_posts(
        self,
        pagination: int = 200,
        page: int = 1,
        post_filter: Optional[PostFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> PostsResponse:
        ignore_invalid_messages = (
            True if ignore_invalid_messages is None else ignore_invalid_messages
        )
        invalid_messages_log_level = (
            logging.NOTSET
            if invalid_messages_log_level is None
            else invalid_messages_log_level
        )

        if not post_filter:
            post_filter = PostFilter()
        params = post_filter.as_http_params()
        params["page"] = str(page)
        params["pagination"] = str(pagination)

        async with self.http_session.get("/api/v0/posts.json", params=params) as resp:
            resp.raise_for_status()
            response_json = await resp.json()
            posts_raw = response_json["posts"]

            posts: List[Post] = []
            for post_raw in posts_raw:
                try:
                    posts.append(Post.parse_obj(post_raw))
                except ValidationError as e:
                    if not ignore_invalid_messages:
                        raise e
                    if invalid_messages_log_level:
                        logger.log(level=invalid_messages_log_level, msg=e)
            return PostsResponse(
                posts=posts,
                pagination_page=response_json["pagination_page"],
                pagination_total=response_json["pagination_total"],
                pagination_per_page=response_json["pagination_per_page"],
                pagination_item=response_json["pagination_item"],
            )

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

        async with self.http_session.get(
            f"/api/v0/storage/raw/{file_hash}"
        ) as response:
            if response.status == 200:
                await copy_async_readable_to_buffer(
                    response.content, output_buffer, chunk_size=16 * 1024
                )
            if response.status == 413:
                ipfs_hash = ItemHash(file_hash)
                if ipfs_hash.item_type == ItemType.ipfs:
                    return await self.download_file_ipfs_to_buffer(
                        file_hash, output_buffer
                    )
                else:
                    raise FileTooLarge(f"The file from {file_hash} is too large")

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
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://ipfs.aleph.im/ipfs/{file_hash}"
            ) as response:
                if response.status == 200:
                    await copy_async_readable_to_buffer(
                        response.content, output_buffer, chunk_size=16 * 1024
                    )
                else:
                    response.raise_for_status()

    async def download_file(
        self,
        file_hash: str,
    ) -> bytes:
        """
        Get a file from the storage engine as raw bytes.

        Warning: Downloading large files can be slow and memory intensive.

        :param file_hash: The hash of the file to retrieve.
        """
        buffer = BytesIO()
        await self.download_file_to_buffer(file_hash, output_buffer=buffer)
        return buffer.getvalue()

    async def download_file_ipfs(
        self,
        file_hash: str,
    ) -> bytes:
        """
        Get a file from the ipfs storage engine as raw bytes.

        Warning: Downloading large files can be slow.

        :param file_hash: The hash of the file to retrieve.
        """
        buffer = BytesIO()
        await self.download_file_ipfs_to_buffer(file_hash, output_buffer=buffer)
        return buffer.getvalue()

    async def get_messages(
        self,
        pagination: int = 200,
        page: int = 1,
        message_filter: Optional[MessageFilter] = None,
        ignore_invalid_messages: Optional[bool] = True,
        invalid_messages_log_level: Optional[int] = logging.NOTSET,
    ) -> MessagesResponse:
        ignore_invalid_messages = (
            True if ignore_invalid_messages is None else ignore_invalid_messages
        )
        invalid_messages_log_level = (
            logging.NOTSET
            if invalid_messages_log_level is None
            else invalid_messages_log_level
        )

        if not message_filter:
            message_filter = MessageFilter()
        params = message_filter.as_http_params()
        params["page"] = str(page)
        params["pagination"] = str(pagination)
        async with self.http_session.get(
            "/api/v0/messages.json", params=params
        ) as resp:
            resp.raise_for_status()
            response_json = await resp.json()
            messages_raw = response_json["messages"]

            # All messages may not be valid according to the latest specification in
            # aleph-message. This allows the user to specify how errors should be handled.
            messages: List[AlephMessage] = []
            for message_raw in messages_raw:
                try:
                    message = parse_message(message_raw)
                    messages.append(message)
                except KeyError as e:
                    if not ignore_invalid_messages:
                        raise e
                    logger.log(
                        level=invalid_messages_log_level,
                        msg=f"KeyError: Field '{e.args[0]}' not found",
                    )
                except ValidationError as e:
                    if not ignore_invalid_messages:
                        raise e
                    if invalid_messages_log_level:
                        logger.log(level=invalid_messages_log_level, msg=e)

            return MessagesResponse(
                messages=messages,
                pagination_page=response_json["pagination_page"],
                pagination_total=response_json["pagination_total"],
                pagination_per_page=response_json["pagination_per_page"],
                pagination_item=response_json["pagination_item"],
            )

    async def get_message(
        self,
        item_hash: str,
        message_type: Optional[Type[GenericMessage]] = None,
        channel: Optional[str] = None,
    ) -> GenericMessage:
        messages_response = await self.get_messages(
            message_filter=MessageFilter(
                hashes=[item_hash],
                channels=[channel] if channel else None,
            )
        )
        if len(messages_response.messages) < 1:
            raise MessageNotFoundError(f"No such hash {item_hash}")
        if len(messages_response.messages) != 1:
            raise MultipleMessagesError(
                f"Multiple messages found for the same item_hash `{item_hash}`"
            )
        message: GenericMessage = messages_response.messages[0]
        if message_type:
            expected_type = get_message_type_value(message_type)
            if message.type != expected_type:
                raise TypeError(
                    f"The message type '{message.type}' "
                    f"does not match the expected type '{expected_type}'"
                )
        return message

    async def watch_messages(
        self,
        message_filter: Optional[MessageFilter] = None,
    ) -> AsyncIterable[AlephMessage]:
        if not message_filter:
            message_filter = MessageFilter()
        params = message_filter.as_http_params()

        async with self.http_session.ws_connect(
            "/api/ws0/messages", params=params
        ) as ws:
            logger.debug("Websocket connected")
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    if msg.data == "close cmd":
                        await ws.close()
                        break
                    else:
                        data = json.loads(msg.data)
                        yield parse_message(data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break


class AuthenticatedAlephClient(AlephClient, BaseAuthenticatedAlephClient):
    account: Account

    BROADCAST_MESSAGE_FIELDS = {
        "sender",
        "chain",
        "signature",
        "type",
        "item_hash",
        "item_type",
        "item_content",
        "time",
        "channel",
    }

    def __init__(
        self,
        account: Account,
        api_server: Optional[str],
        api_unix_socket: Optional[str] = None,
        allow_unix_sockets: bool = True,
        timeout: Optional[aiohttp.ClientTimeout] = None,
    ):
        super().__init__(
            api_server=api_server,
            api_unix_socket=api_unix_socket,
            allow_unix_sockets=allow_unix_sockets,
            timeout=timeout,
        )
        self.account = account

    def __enter__(self) -> "AuthenticatedUserSessionSync":
        return AuthenticatedUserSessionSync(async_session=self)

    async def __aenter__(self) -> "AuthenticatedAlephClient":
        return self

    async def ipfs_push(self, content: Mapping) -> str:
        """
        Push arbitrary content as JSON to the IPFS service.

        :param content: The dict-like content to upload
        """
        url = "/api/v0/ipfs/add_json"
        logger.debug(f"Pushing to IPFS on {url}")

        async with self.http_session.post(url, json=content) as resp:
            resp.raise_for_status()
            return (await resp.json()).get("hash")

    async def storage_push(self, content: Mapping) -> str:
        """
        Push arbitrary content as JSON to the storage service.

        :param content: The dict-like content to upload
        """
        url = "/api/v0/storage/add_json"
        logger.debug(f"Pushing to storage on {url}")

        async with self.http_session.post(url, json=content) as resp:
            resp.raise_for_status()
            return (await resp.json()).get("hash")

    async def ipfs_push_file(self, file_content: Union[str, bytes]) -> str:
        """
        Push a file to the IPFS service.

        :param file_content: The file content to upload
        """
        data = aiohttp.FormData()
        data.add_field("file", file_content)

        url = "/api/v0/ipfs/add_file"
        logger.debug(f"Pushing file to IPFS on {url}")

        async with self.http_session.post(url, data=data) as resp:
            resp.raise_for_status()
            return (await resp.json()).get("hash")

    async def storage_push_file(self, file_content) -> str:
        """
        Push a file to the storage service.
        """
        data = aiohttp.FormData()
        data.add_field("file", file_content)

        url = "/api/v0/storage/add_file"
        logger.debug(f"Posting file on {url}")

        async with self.http_session.post(url, data=data) as resp:
            resp.raise_for_status()
            return (await resp.json()).get("hash")

    @staticmethod
    def _log_publication_status(publication_status: Mapping[str, Any]):
        status = publication_status.get("status")
        failures = publication_status.get("failed")

        if status == "success":
            return
        elif status == "warning":
            logger.warning("Broadcast failed on the following network(s): %s", failures)
        elif status == "error":
            logger.error(
                "Broadcast failed on all protocols. The message was not published."
            )
        else:
            raise ValueError(
                f"Invalid response from server, status in missing or unknown: '{status}'"
            )

    @staticmethod
    async def _handle_broadcast_error(response: aiohttp.ClientResponse) -> NoReturn:
        if response.status == 500:
            # Assume a broadcast error, no need to read the JSON
            if response.content_type == "application/json":
                error_msg = "Internal error - broadcast failed on all protocols"
            else:
                error_msg = f"Internal error - the message was not broadcast: {await response.text()}"

            logger.error(error_msg)
            raise BroadcastError(error_msg)
        elif response.status == 422:
            errors = await response.json()
            logger.error(
                "The message could not be processed because of the following errors: %s",
                errors,
            )
            raise InvalidMessageError(errors)
        else:
            error_msg = (
                f"Unexpected HTTP response ({response.status}: {await response.text()})"
            )
            logger.error(error_msg)
            raise BroadcastError(error_msg)

    async def _handle_broadcast_deprecated_response(
        self,
        response: aiohttp.ClientResponse,
    ) -> None:
        if response.status != 200:
            await self._handle_broadcast_error(response)
        else:
            publication_status = await response.json()
            self._log_publication_status(publication_status)

    async def _broadcast_deprecated(self, message_dict: Mapping[str, Any]) -> None:
        """
        Broadcast a message on the aleph.im network using the deprecated
        /ipfs/pubsub/pub/ endpoint.
        """

        url = "/api/v0/ipfs/pubsub/pub"
        logger.debug(f"Posting message on {url}")

        async with self.http_session.post(
            url,
            json={"topic": "ALEPH-TEST", "data": json.dumps(message_dict)},
        ) as response:
            await self._handle_broadcast_deprecated_response(response)

    async def _handle_broadcast_response(
        self, response: aiohttp.ClientResponse, sync: bool
    ) -> MessageStatus:
        if response.status in (200, 202):
            status = await response.json()
            self._log_publication_status(status["publication_status"])

            if response.status == 202:
                if sync:
                    logger.warning(
                        "Timed out while waiting for processing of sync message"
                    )
                return MessageStatus.PENDING

            return MessageStatus.PROCESSED

        else:
            await self._handle_broadcast_error(response)

    async def _broadcast(
        self,
        message: AlephMessage,
        sync: bool,
    ) -> MessageStatus:
        """
        Broadcast a message on the aleph.im network.

        Uses the POST /messages/ endpoint or the deprecated /ipfs/pubsub/pub/ endpoint
        if the first method is not available.
        """

        url = "/api/v0/messages"
        logger.debug(f"Posting message on {url}")

        message_dict = message.dict(include=self.BROADCAST_MESSAGE_FIELDS)

        async with self.http_session.post(
            url,
            json={"sync": sync, "message": message_dict},
        ) as response:
            # The endpoint may be unavailable on this node, try the deprecated version.
            if response.status in (404, 405):
                logger.warning(
                    "POST /messages/ not found. Defaulting to legacy endpoint..."
                )
                await self._broadcast_deprecated(message_dict=message_dict)
                return MessageStatus.PENDING
            else:
                message_status = await self._handle_broadcast_response(
                    response=response, sync=sync
                )
                return message_status

    async def create_post(
        self,
        post_content,
        post_type: str,
        ref: Optional[str] = None,
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        storage_engine: StorageEnum = StorageEnum.storage,
        sync: bool = False,
    ) -> Tuple[PostMessage, MessageStatus]:
        address = address or settings.ADDRESS_TO_USE or self.account.get_address()

        content = PostContent(
            type=post_type,
            address=address,
            content=post_content,
            time=time.time(),
            ref=ref,
        )

        return await self.submit(
            content=content.dict(exclude_none=True),
            message_type=MessageType.post,
            channel=channel,
            allow_inlining=inline,
            storage_engine=storage_engine,
            sync=sync,
        )

    async def create_aggregate(
        self,
        key: str,
        content: Mapping[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        sync: bool = False,
    ) -> Tuple[AggregateMessage, MessageStatus]:
        address = address or settings.ADDRESS_TO_USE or self.account.get_address()

        content_ = AggregateContent(
            key=key,
            address=address,
            content=content,
            time=time.time(),
        )

        return await self.submit(
            content=content_.dict(exclude_none=True),
            message_type=MessageType.aggregate,
            channel=channel,
            allow_inlining=inline,
            sync=sync,
        )

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
    ) -> Tuple[StoreMessage, MessageStatus]:
        address = address or settings.ADDRESS_TO_USE or self.account.get_address()

        extra_fields = extra_fields or {}

        if file_hash is None:
            if file_content is None:
                if file_path is None:
                    raise ValueError(
                        "Please specify at least a file_content, a file_hash or a file_path"
                    )
                else:
                    file_content = Path(file_path).read_bytes()

            if storage_engine == StorageEnum.storage:
                file_hash = await self.storage_push_file(file_content=file_content)
            elif storage_engine == StorageEnum.ipfs:
                file_hash = await self.ipfs_push_file(file_content=file_content)
            else:
                raise ValueError(f"Unknown storage engine: '{storage_engine}'")

        assert file_hash, "File hash should not be empty"

        if magic is None:
            pass
        elif file_content and guess_mime_type and ("mime_type" not in extra_fields):
            extra_fields["mime_type"] = magic.from_buffer(file_content, mime=True)

        if ref:
            extra_fields["ref"] = ref

        values = {
            "address": address,
            "item_type": storage_engine,
            "item_hash": file_hash,
            "time": time.time(),
        }
        if extra_fields is not None:
            values.update(extra_fields)

        content = StoreContent(**values)

        return await self.submit(
            content=content.dict(exclude_none=True),
            message_type=MessageType.store,
            channel=channel,
            allow_inlining=True,
            sync=sync,
        )

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
    ) -> Tuple[ProgramMessage, MessageStatus]:
        address = address or settings.ADDRESS_TO_USE or self.account.get_address()

        volumes = volumes if volumes is not None else []
        memory = memory or settings.DEFAULT_VM_MEMORY
        vcpus = vcpus or settings.DEFAULT_VM_VCPUS
        timeout_seconds = timeout_seconds or settings.DEFAULT_VM_TIMEOUT

        # TODO: Check that program_ref, runtime and data_ref exist

        # Register the different ways to trigger a VM
        if subscriptions:
            # Trigger on HTTP calls and on aleph.im message subscriptions.
            triggers = {
                "http": True,
                "persistent": persistent,
                "message": subscriptions,
            }
        else:
            # Trigger on HTTP calls.
            triggers = {"http": True, "persistent": persistent}

        content = ProgramContent(
            **{
                "type": "vm-function",
                "address": address,
                "allow_amend": False,
                "code": {
                    "encoding": encoding,
                    "entrypoint": entrypoint,
                    "ref": program_ref,
                    "use_latest": True,
                },
                "on": triggers,
                "environment": {
                    "reproducible": False,
                    "internet": True,
                    "aleph_api": True,
                },
                "variables": environment_variables,
                "resources": {
                    "vcpus": vcpus,
                    "memory": memory,
                    "seconds": timeout_seconds,
                },
                "runtime": {
                    "ref": runtime,
                    "use_latest": True,
                    "comment": "Official aleph.im runtime"
                    if runtime == settings.DEFAULT_RUNTIME_ID
                    else "",
                },
                "volumes": volumes,
                "time": time.time(),
                "metadata": metadata,
            }
        )

        # Ensure that the version of aleph-message used supports the field.
        assert content.on.persistent == persistent

        return await self.submit(
            content=content.dict(exclude_none=True),
            message_type=MessageType.program,
            channel=channel,
            storage_engine=storage_engine,
            sync=sync,
        )

    async def forget(
        self,
        hashes: List[str],
        reason: Optional[str],
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[ForgetMessage, MessageStatus]:
        address = address or settings.ADDRESS_TO_USE or self.account.get_address()

        content = ForgetContent(
            hashes=hashes,
            reason=reason,
            address=address,
            time=time.time(),
        )

        return await self.submit(
            content=content.dict(exclude_none=True),
            message_type=MessageType.forget,
            channel=channel,
            storage_engine=storage_engine,
            allow_inlining=True,
            sync=sync,
        )

    @staticmethod
    def compute_sha256(s: str) -> str:
        h = hashlib.sha256()
        h.update(s.encode("utf-8"))
        return h.hexdigest()

    async def _prepare_aleph_message(
        self,
        message_type: MessageType,
        content: Dict[str, Any],
        channel: Optional[str],
        allow_inlining: bool = True,
        storage_engine: StorageEnum = StorageEnum.storage,
    ) -> AlephMessage:
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
            content, separators=(",", ":"), default=pydantic_encoder
        )

        if allow_inlining and (len(item_content) < settings.MAX_INLINE_SIZE):
            message_dict["item_content"] = item_content
            message_dict["item_hash"] = self.compute_sha256(item_content)
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

    async def submit(
        self,
        content: Dict[str, Any],
        message_type: MessageType,
        channel: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        allow_inlining: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        message = await self._prepare_aleph_message(
            message_type=message_type,
            content=content,
            channel=channel,
            allow_inlining=allow_inlining,
            storage_engine=storage_engine,
        )
        message_status = await self._broadcast(message=message, sync=sync)
        return message, message_status
