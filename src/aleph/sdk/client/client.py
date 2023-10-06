import asyncio
import json
import logging
import queue
import threading
from io import BytesIO
from typing import (
    Any,
    AsyncIterable,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Type,
)

import aiohttp
from aleph_message import parse_message
from aleph_message.models import AlephMessage, ItemHash, ItemType
from pydantic import ValidationError

from ..conf import settings
from ..exceptions import FileTooLarge, MessageNotFoundError, MultipleMessagesError
from ..models.message import MessageFilter, MessagesResponse
from ..models.post import Post, PostFilter, PostsResponse
from ..types import GenericMessage
from ..utils import (
    Writable,
    check_unix_socket_valid,
    copy_async_readable_to_buffer,
    get_message_type_value,
)
from .base import BaseAlephClient
from .utils import T, wrap_async

logger = logging.getLogger(__name__)


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
        page_size: int = 200,
        page: int = 1,
        message_filter: Optional[MessageFilter] = None,
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ) -> MessagesResponse:
        return self._wrap(
            self.async_session.get_messages,
            page_size=page_size,
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
    ) -> Dict[str, Dict]:
        return self._wrap(self.async_session.fetch_aggregate, address, key)

    def fetch_aggregates(
        self,
        address: str,
        keys: Optional[Iterable[str]] = None,
    ) -> Dict[str, Dict]:
        return self._wrap(self.async_session.fetch_aggregates, address, keys)

    def get_posts(
        self,
        page_size: int = 200,
        page: int = 1,
        post_filter: Optional[PostFilter] = None,
    ) -> PostsResponse:
        return self._wrap(
            self.async_session.get_posts,
            page_size=page_size,
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
            resp.raise_for_status()
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
            resp.raise_for_status()
            result = await resp.json()
            data = result.get("data", dict())
            return data

    async def get_posts(
        self,
        page_size: int = 200,
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
        params["pagination"] = str(page_size)

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
        page_size: int = 200,
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
        params["pagination"] = str(page_size)
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
