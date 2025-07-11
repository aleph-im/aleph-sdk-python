import hashlib
import json
import logging
import ssl
import time
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Mapping, NoReturn, Optional, Tuple, Union

import aiohttp
from aleph_message.models import (
    AggregateContent,
    AggregateMessage,
    AlephMessage,
    ForgetContent,
    ForgetMessage,
    InstanceMessage,
    ItemHash,
    ItemType,
    MessageType,
    PostContent,
    PostMessage,
    ProgramMessage,
    StoreContent,
    StoreMessage,
)
from aleph_message.models.execution.base import Encoding, Payment
from aleph_message.models.execution.environment import (
    HostRequirements,
    HypervisorType,
    TrustedExecutionEnvironment,
)
from aleph_message.status import MessageStatus

from ..conf import settings
from ..exceptions import BroadcastError, InsufficientFundsError, InvalidMessageError
from ..types import Account, StorageEnum, TokenType
from ..utils import extended_json_encoder, make_instance_content, make_program_content
from .abstract import AuthenticatedAlephClient
from .http import AlephHttpClient
from .services.authenticated_port_forwarder import AuthenticatedPortForwarder

logger = logging.getLogger(__name__)

try:
    import magic
except ImportError:
    logger.info("Could not import library 'magic', MIME type detection disabled")
    magic = None  # type:ignore


class AuthenticatedAlephHttpClient(AlephHttpClient, AuthenticatedAlephClient):
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
        api_server: Optional[str] = None,
        api_unix_socket: Optional[str] = None,
        allow_unix_sockets: bool = True,
        timeout: Optional[aiohttp.ClientTimeout] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):
        super().__init__(
            api_server=api_server,
            api_unix_socket=api_unix_socket,
            allow_unix_sockets=allow_unix_sockets,
            timeout=timeout,
            ssl_context=ssl_context,
        )
        self.account = account

    async def __aenter__(self):
        await super().__aenter__()
        # Override services with authenticated versions
        self.port_forwarder = AuthenticatedPortForwarder(self)

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

    async def ipfs_push_file(self, file_content: bytes) -> str:
        """
        Push a file to the IPFS service.

        :param file_content: The file content to upload
        """
        data = aiohttp.FormData()
        data.add_field("file", BytesIO(file_content))

        url = "/api/v0/ipfs/add_file"
        logger.debug(f"Pushing file to IPFS on {url}")

        async with self.http_session.post(url, data=data) as resp:
            resp.raise_for_status()
            return (await resp.json()).get("hash")

    async def storage_push_file(self, file_content: bytes) -> Optional[str]:
        """
        Push a file to the storage service.
        """
        data = aiohttp.FormData()
        data.add_field("file", BytesIO(file_content))

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
            try:
                errors = await response.json()
                logger.error(
                    "The message could not be processed because of the following errors: %s",
                    errors,
                )
                raise InvalidMessageError(errors)
            except (json.JSONDecodeError, aiohttp.client_exceptions.ContentTypeError):
                error = await response.text()
                logger.error(
                    "The message could not be processed because of the following errors: %s",
                    error,
                )
                raise InvalidMessageError(error)
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
            json={
                "topic": "ALEPH-TEST",
                "data": message_dict,
            },
        ) as response:
            await self._handle_broadcast_deprecated_response(response)

    async def _handle_broadcast_response(
        self, response: aiohttp.ClientResponse, sync: bool, raise_on_rejected: bool
    ) -> Tuple[Dict[str, Any], MessageStatus]:
        if response.status in (200, 202):
            status = await response.json()
            self._log_publication_status(status["publication_status"])

            if response.status == 202:
                if sync:
                    logger.warning(
                        "Timed out while waiting for processing of sync message"
                    )
                return status, MessageStatus.PENDING

            return status, MessageStatus.PROCESSED
        elif response.status == 422 and not raise_on_rejected:
            return await response.json(), MessageStatus.REJECTED
        else:
            await self._handle_broadcast_error(response)

    async def _broadcast(
        self,
        message: AlephMessage,
        sync: bool,
        raise_on_rejected: bool = True,
    ) -> Tuple[Dict[str, Any], MessageStatus]:
        """
        Broadcast a message on the aleph.im network.

        Uses the POST /messages/ endpoint or the deprecated /ipfs/pubsub/pub/ endpoint
        if the first method is not available.
        """

        url = "/api/v0/messages"
        logger.debug(f"Posting message on {url}")

        message_dict = message.model_dump(include=self.BROADCAST_MESSAGE_FIELDS)
        async with self.http_session.post(
            url,
            json={
                "sync": sync,
                "message": message_dict,
            },
        ) as response:
            # The endpoint may be unavailable on this node, try the deprecated version.
            if response.status in (404, 405):
                logger.warning(
                    "POST /messages/ not found. Defaulting to legacy endpoint..."
                )
                await self._broadcast_deprecated(message_dict=message_dict)
                return await response.json(), MessageStatus.PENDING
            else:
                return await self._handle_broadcast_response(
                    response=response, sync=sync, raise_on_rejected=raise_on_rejected
                )

    async def create_post(
        self,
        post_content,
        post_type: str,
        ref: Optional[str] = None,
        address: Optional[str] = None,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
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

        message, status, _ = await self.submit(
            content=content.model_dump(exclude_none=True),
            message_type=MessageType.post,
            channel=channel,
            allow_inlining=inline,
            storage_engine=storage_engine,
            sync=sync,
        )
        return message, status  # type: ignore

    async def create_aggregate(
        self,
        key: str,
        content: dict[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
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

        message, status, _ = await self.submit(
            content=content_.model_dump(exclude_none=True),
            message_type=MessageType.aggregate,
            channel=channel,
            allow_inlining=inline,
            sync=sync,
        )
        return message, status  # type: ignore

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
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
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
                # Upload the file and message all at once using authenticated upload.
                return await self._upload_file_native(
                    address=address,
                    file_content=file_content,
                    guess_mime_type=guess_mime_type,
                    ref=ref,
                    extra_fields=extra_fields,
                    channel=channel,
                    sync=sync,
                )
            elif storage_engine == StorageEnum.ipfs:
                # We do not support authenticated upload for IPFS yet. Use the legacy method
                # of uploading the file first then publishing the message using POST /messages.
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

        content = StoreContent.model_validate(values)

        message, status, _ = await self.submit(
            content=content.model_dump(exclude_none=True),
            message_type=MessageType.store,
            channel=channel,
            allow_inlining=True,
            sync=sync,
        )
        return message, status  # type: ignore

    async def create_program(
        self,
        program_ref: str,
        entrypoint: str,
        runtime: str,
        metadata: Optional[dict[str, Any]] = None,
        address: Optional[str] = None,
        payment: Optional[Payment] = None,
        vcpus: Optional[int] = None,
        memory: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        internet: bool = True,
        allow_amend: bool = False,
        aleph_api: bool = True,
        encoding: Encoding = Encoding.zip,
        persistent: bool = False,
        volumes: Optional[list[Mapping]] = None,
        environment_variables: Optional[dict[str, str]] = None,
        subscriptions: Optional[list[dict]] = None,
        sync: bool = False,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
        storage_engine: StorageEnum = StorageEnum.storage,
    ) -> Tuple[ProgramMessage, MessageStatus]:
        address = address or settings.ADDRESS_TO_USE or self.account.get_address()

        content = make_program_content(
            program_ref=program_ref,
            entrypoint=entrypoint,
            runtime=runtime,
            metadata=metadata,
            address=address,
            payment=payment,
            vcpus=vcpus,
            memory=memory,
            timeout_seconds=timeout_seconds,
            internet=internet,
            aleph_api=aleph_api,
            allow_amend=allow_amend,
            encoding=encoding,
            persistent=persistent,
            volumes=volumes,
            environment_variables=environment_variables,
            subscriptions=subscriptions,
        )

        message, status, _ = await self.submit(
            content=content.model_dump(exclude_none=True),
            message_type=MessageType.program,
            channel=channel,
            storage_engine=storage_engine,
            sync=sync,
            raise_on_rejected=False,
        )
        if status in (MessageStatus.PROCESSED, MessageStatus.PENDING):
            return message, status  # type: ignore

        # get the reason for rejection
        rejected_message = await self.get_message_error(message.item_hash)
        assert rejected_message, "No rejected message found"
        error_code = rejected_message["error_code"]
        if error_code == 5:
            # not enough balance
            details = rejected_message["details"]
            errors = details["errors"]
            error = errors[0]
            account_balance = float(error["account_balance"])
            required_balance = float(error["required_balance"])
            raise InsufficientFundsError(
                token_type=TokenType.ALEPH,
                required_funds=required_balance,
                available_funds=account_balance,
            )
        else:
            raise ValueError(f"Unknown error code {error_code}: {rejected_message}")

    async def create_instance(
        self,
        rootfs: str,
        rootfs_size: int,
        payment: Optional[Payment] = None,
        environment_variables: Optional[dict[str, str]] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
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
        volumes: Optional[list[Mapping]] = None,
        volume_persistence: str = "host",
        ssh_keys: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        requirements: Optional[HostRequirements] = None,
    ) -> Tuple[InstanceMessage, MessageStatus]:
        address = address or settings.ADDRESS_TO_USE or self.account.get_address()

        content = make_instance_content(
            rootfs=rootfs,
            rootfs_size=rootfs_size,
            payment=payment,
            environment_variables=environment_variables,
            address=address,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            allow_amend=allow_amend,
            internet=internet,
            aleph_api=aleph_api,
            hypervisor=hypervisor,
            trusted_execution=trusted_execution,
            volumes=volumes,
            ssh_keys=ssh_keys,
            metadata=metadata,
            requirements=requirements,
        )

        message, status, response = await self.submit(
            content=content.model_dump(exclude_none=True),
            message_type=MessageType.instance,
            channel=channel,
            storage_engine=storage_engine,
            sync=sync,
            raise_on_rejected=False,
        )
        if status in (MessageStatus.PROCESSED, MessageStatus.PENDING):
            return message, status  # type: ignore

        # get the reason for rejection
        rejected_message = await self.get_message_error(message.item_hash)
        assert rejected_message, "No rejected message found"
        error_code = rejected_message["error_code"]
        if error_code == 5:
            # not enough balance
            details = rejected_message["details"]
            errors = details["errors"]
            error = errors[0]
            account_balance = float(error["account_balance"])
            required_balance = float(error["required_balance"])
            raise InsufficientFundsError(
                token_type=TokenType.ALEPH,
                required_funds=required_balance,
                available_funds=account_balance,
            )
        else:
            raise ValueError(f"Unknown error code {error_code}: {rejected_message}")

    async def forget(
        self,
        hashes: list[ItemHash],
        reason: Optional[str],
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
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

        message, status, _ = await self.submit(
            content=content.model_dump(exclude_none=True),
            message_type=MessageType.forget,
            channel=channel,
            storage_engine=storage_engine,
            allow_inlining=True,
            sync=sync,
        )
        return message, status  # type: ignore

    async def submit(
        self,
        content: Dict[str, Any],
        message_type: MessageType,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
        storage_engine: StorageEnum = StorageEnum.storage,
        allow_inlining: bool = True,
        sync: bool = False,
        raise_on_rejected: bool = True,
    ) -> Tuple[AlephMessage, MessageStatus, Optional[Dict[str, Any]]]:
        message = await self.generate_signed_message(
            message_type=message_type,
            content=content,
            channel=channel,
            allow_inlining=allow_inlining,
            storage_engine=storage_engine,
        )
        response, message_status = await self._broadcast(
            message=message, sync=sync, raise_on_rejected=raise_on_rejected
        )
        return message, message_status, response

    async def _storage_push_file_with_message(
        self,
        file_content: bytes,
        store_content: StoreContent,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
        sync: bool = False,
    ) -> Tuple[StoreMessage, MessageStatus]:
        """Push a file to the storage service."""
        data = aiohttp.FormData()

        # Prepare the STORE message
        message = await self.generate_signed_message(
            message_type=MessageType.store,
            content=store_content.model_dump(exclude_none=True),
            channel=channel,
        )
        metadata = {
            "message": message.model_dump(exclude_none=True),
            "sync": sync,
        }
        data.add_field(
            "metadata",
            json.dumps(metadata, default=extended_json_encoder),
            content_type="application/json",
        )
        # Add the file
        data.add_field("file", BytesIO(file_content))

        url = "/api/v0/storage/add_file"
        logger.debug(f"Posting file on {url}")

        async with self.http_session.post(url, data=data) as resp:
            resp.raise_for_status()
            message_status = (
                MessageStatus.PENDING if resp.status == 202 else MessageStatus.PROCESSED
            )
            return message, message_status  # type: ignore

    async def _upload_file_native(
        self,
        address: str,
        file_content: bytes,
        guess_mime_type: bool = False,
        ref: Optional[str] = None,
        extra_fields: Optional[dict] = None,
        channel: Optional[str] = settings.DEFAULT_CHANNEL,
        sync: bool = False,
    ) -> Tuple[StoreMessage, MessageStatus]:
        file_hash = hashlib.sha256(file_content).hexdigest()
        if magic and guess_mime_type:
            mime_type = magic.from_buffer(file_content, mime=True)
        else:
            mime_type = None

        store_content = StoreContent(
            address=address,
            ref=ref,
            item_type=ItemType.storage,
            item_hash=ItemHash(file_hash),
            mime_type=mime_type,  # type: ignore
            time=time.time(),
            **(extra_fields or {}),
        )
        message, _ = await self._storage_push_file_with_message(
            file_content=file_content,
            store_content=store_content,
            channel=channel,
            sync=sync,
        )

        # Some nodes may not implement authenticated file upload yet. As we cannot detect
        # this easily, broadcast the message a second time to ensure publication on older
        # nodes.
        _, status = await self._broadcast(message=message, sync=sync)
        return message, status
