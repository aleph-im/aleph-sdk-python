import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, NoReturn, Optional, Tuple, Union

import aiohttp
from aleph_message import parse_message
from aleph_message.models import (
    AggregateContent,
    AggregateMessage,
    AlephMessage,
    ForgetContent,
    ForgetMessage,
    ItemType,
    MessageType,
    PostContent,
    PostMessage,
    ProgramContent,
    ProgramMessage,
    StoreContent,
    StoreMessage,
)
from aleph_message.models.execution.base import Encoding
from aleph_message.status import MessageStatus
from pydantic.json import pydantic_encoder

from ..conf import settings
from ..exceptions import BroadcastError, InvalidMessageError
from ..types import Account, StorageEnum
from .base import BaseAuthenticatedAlephClient
from .client import AlephClient, UserSessionSync

logger = logging.getLogger(__name__)

try:
    import magic
except ImportError:
    logger.info("Could not import library 'magic', MIME type detection disabled")
    magic = None  # type:ignore


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
