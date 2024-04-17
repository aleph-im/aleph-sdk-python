import json
import logging
import os.path
import ssl
from io import BytesIO
from pathlib import Path
from typing import Any, AsyncIterable, Dict, Iterable, List, Optional, Type, Union

import aiohttp
from aleph_message import parse_message
from aleph_message.models import AlephMessage, ItemHash, ItemType
from pydantic import ValidationError

from ..conf import settings
from ..exceptions import FileTooLarge, ForgottenMessageError, MessageNotFoundError
from ..query.filters import MessageFilter, PostFilter
from ..query.responses import MessagesResponse, Post, PostsResponse
from ..types import GenericMessage
from ..utils import (
    Writable,
    check_unix_socket_valid,
    copy_async_readable_to_buffer,
    extended_json_encoder,
    get_message_type_value,
)
from .abstract import AlephClient

logger = logging.getLogger(__name__)


class AlephHttpClient(AlephClient):
    api_server: str
    http_session: aiohttp.ClientSession

    def __init__(
        self,
        api_server: Optional[str] = None,
        api_unix_socket: Optional[str] = None,
        allow_unix_sockets: bool = True,
        timeout: Optional[aiohttp.ClientTimeout] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):
        """AlephClient can use HTTP(S) or HTTP over Unix sockets.
        Unix sockets are used when running inside a virtual machine,
        and can be shared across containers in a more secure way than TCP ports.
        """
        self.api_server = api_server or settings.API_HOST
        if not self.api_server:
            raise ValueError("Missing API host")

        connector: Union[aiohttp.BaseConnector, None]
        unix_socket_path = api_unix_socket or settings.API_UNIX_SOCKET
        if ssl_context:
            connector = aiohttp.TCPConnector(ssl=ssl_context)
        elif unix_socket_path and allow_unix_sockets:
            check_unix_socket_valid(unix_socket_path)
            connector = aiohttp.UnixConnector(path=unix_socket_path)
        else:
            connector = None

        # ClientSession timeout defaults to a private sentinel object and may not be None.
        self.http_session = (
            aiohttp.ClientSession(
                base_url=self.api_server,
                connector=connector,
                timeout=timeout,
                json_serialize=extended_json_encoder,
            )
            if timeout
            else aiohttp.ClientSession(
                base_url=self.api_server,
                connector=connector,
                json_serialize=lambda obj: json.dumps(
                    obj, default=extended_json_encoder
                ),
            )
        )

    async def __aenter__(self) -> "AlephHttpClient":
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
            params = {
                "page": str(page),
                "pagination": str(page_size),
            }
        else:
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

    async def download_file(self, file_hash: str) -> bytes:
        """
        Get a file from the storage engine as raw bytes.

        Warning: Downloading large files can be slow and memory intensive. Use `download_file_to()` to download them directly to disk instead.

        :param file_hash: The hash of the file to retrieve.
        """
        buffer = BytesIO()
        await self.download_file_to_buffer(file_hash, output_buffer=buffer)
        return buffer.getvalue()

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
        if not isinstance(path, Path):
            path = Path(path)

        if not os.path.exists(path):
            dir_path = os.path.dirname(path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)

        with open(path, "wb") as file_buffer:
            await self.download_file_to_buffer(file_hash, output_buffer=file_buffer)

        return path

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
            params = {
                "page": str(page),
                "pagination": str(page_size),
            }
        else:
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
    ) -> GenericMessage:
        async with self.http_session.get(f"/api/v0/messages/{item_hash}") as resp:
            try:
                resp.raise_for_status()
            except aiohttp.ClientResponseError as e:
                if e.status == 404:
                    raise MessageNotFoundError(f"No such hash {item_hash}")
                raise e
            message_raw = await resp.json()
        if message_raw["status"] == "forgotten":
            raise ForgottenMessageError(
                f"The requested message {message_raw['item_hash']} has been forgotten by {', '.join(message_raw['forgotten_by'])}"
            )
        message = parse_message(message_raw["message"])
        if message_type:
            expected_type = get_message_type_value(message_type)
            if message.type != expected_type:
                raise TypeError(
                    f"The message type '{message.type}' "
                    f"does not match the expected type '{expected_type}'"
                )
        return message

    async def get_message_error(
        self,
        item_hash: str,
    ) -> Optional[Dict[str, Any]]:
        async with self.http_session.get(f"/api/v0/messages/{item_hash}") as resp:
            try:
                resp.raise_for_status()
            except aiohttp.ClientResponseError as e:
                if e.status == 404:
                    raise MessageNotFoundError(f"No such hash {item_hash}")
                raise e
            message_raw = await resp.json()
        if message_raw["status"] == "forgotten":
            raise ForgottenMessageError(
                f"The requested message {message_raw['item_hash']} has been forgotten by {', '.join(message_raw['forgotten_by'])}"
            )
        if message_raw["status"] != "rejected":
            return None
        return {
            "error_code": message_raw["error_code"],
            "details": message_raw["details"],
        }

    async def watch_messages(
        self,
        message_filter: Optional[MessageFilter] = None,
    ) -> AsyncIterable[AlephMessage]:
        message_filter = message_filter or MessageFilter()
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
