import asyncio
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from aleph_message.models import AlephMessage, Chain, MessageType
from aleph_message.models.execution.base import Encoding, Payment
from aleph_message.status import MessageStatus

from ..query.filters import MessageFilter
from ..types import StorageEnum
from ..utils import Writable
from .abstract import AuthenticatedAlephClient
from .authenticated_http import AuthenticatedAlephHttpClient
from .message_cache import MessageCache


class LightNode(MessageCache, AuthenticatedAlephClient):
    """
    A LightNode is a client that can listen to the Aleph network and stores messages in a local database. Furthermore,
    it can create messages and submit them to the network, as well as upload files, while keeping track of the
    corresponding messages locally.

    It synchronizes with the network on a subset of the messages (the "domain") by listening to the network and storing
    the messages in the database. The user may define the domain by specifying a channels, tags, senders, chains and/or
    message types.
    """

    def __init__(
        self,
        session: AuthenticatedAlephHttpClient,
        channels: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[Chain]] = None,
        message_types: Optional[Iterable[MessageType]] = None,
    ):
        """
        Initialize a LightNode. Besides requiring an established session with a core channel node, the user may specify
        a domain to listen to. The domain is the intersection of the specified channels, tags, senders, chains and
        message types. A smaller domain will synchronize faster, require less storage and less bandwidth.

        Args:
            session: An authenticated session to an Aleph core channel node.
            channels: The channels to listen to.
            tags: The tags to listen to.
            addresses: The addresses to listen to.
            chains: The chains to listen to.
            message_types: The message types to listen to.

        Raises:
            InvalidCacheDatabaseSchema: If the database schema does not match the expected message schema.
        """
        super().__init__()
        self.session = session
        self.channels = channels
        self.tags = tags
        self.addresses = (
            list(addresses) + [session.account.get_address()]
            if addresses
            else [session.account.get_address()]
        )
        self.chains = (
            list(chains) + [Chain(session.account.CHAIN)]
            if chains
            else [session.account.CHAIN]
        )
        self.message_types = message_types

    async def run(self):
        """
        Start listening to the network and synchronize with past messages.
        """
        asyncio.create_task(
            self.listen_to(
                self.session.watch_messages(
                    message_filter=MessageFilter(
                        channels=self.channels,
                        tags=self.tags,
                        addresses=self.addresses,
                        chains=self.chains,
                        message_types=self.message_types,
                    )
                )
            )
        )
        # synchronize with past messages
        await self.synchronize(
            channels=self.channels,
            tags=self.tags,
            addresses=self.addresses,
            chains=self.chains,
            message_types=self.message_types,
        )

    async def synchronize(
        self,
        channels: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[Chain]] = None,
        message_types: Optional[Iterable[MessageType]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
    ):
        """
        Synchronize with past messages.
        """
        chunk_size = 200
        messages = []
        async for message in self.session.get_messages_iterator(
            message_filter=MessageFilter(
                channels=channels,
                tags=tags,
                addresses=addresses,
                chains=chains,
                message_types=message_types,
                start_date=start_date,
                end_date=end_date,
            )
        ):
            messages.append(message)
            if len(messages) >= chunk_size:
                self.add(messages)
                messages = []
        if messages:
            self.add(messages)

    async def download_file(self, file_hash: str) -> bytes:
        """
        Download a file from the network and store it locally. If it already exists locally, it will not be downloaded
        again.

        Args:
            file_hash: The hash of the file to download.

        Returns:
            The file content.

        Raises:
            FileNotFoundError: If the file does not exist on the network.
        """
        try:
            return await super().download_file(file_hash)
        except FileNotFoundError:
            pass
        file = await self.session.download_file(file_hash)
        self._file_path(file_hash).parent.mkdir(parents=True, exist_ok=True)
        with open(self._file_path(file_hash), "wb") as f:
            f.write(file)
        return file

    async def download_file_to_buffer(
        self,
        file_hash: str,
        output_buffer: Writable[bytes],
    ) -> None:
        """
        Download a file from the network and store it in a buffer. If it already exists locally, it will not be
        downloaded again.

        Args:
            file_hash: The hash of the file to download.
            output_buffer: The buffer to store the file content in.

        Raises:
            FileNotFoundError: If the file does not exist on the network.
        """
        try:
            return await super().download_file_to_buffer(file_hash, output_buffer)
        except FileNotFoundError:
            pass
        buffer = BytesIO()
        await self.session.download_file_ipfs_to_buffer(file_hash, buffer)
        self._file_path(file_hash).parent.mkdir(parents=True, exist_ok=True)
        with open(self._file_path(file_hash), "wb") as f:
            f.write(buffer.getvalue())
        output_buffer.write(buffer.getvalue())

    def check_validity(
        self,
        message_type: MessageType,
        address: Optional[str] = None,
        channel: Optional[str] = None,
        content: Optional[Dict] = None,
    ):
        if self.message_types and message_type not in self.message_types:
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to post messages."
            )
        if address and self.addresses and address not in self.addresses:
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to messages from address {address}."
            )
        if channel and self.channels and channel not in self.channels:
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to messages from channel {channel}."
            )
        if (
            content
            and self.tags
            and not set(content.get("tags", [])).intersection(self.tags)
        ):
            raise ValueError(
                f"Cannot create {message_type.value} message because DomainNode is not listening to any of these tags: {content.get('tags', [])}."
            )

    async def delete_if_rejected(self, item_hash):
        async def _delete_if_rejected():
            await asyncio.sleep(5)
            retries = 0
            status = await self.session.get_message_status(item_hash)
            while status == MessageStatus.PENDING:
                await asyncio.sleep(5)
                status = await self.session.get_message_status(item_hash)
                retries += 1
                if retries > 10:
                    raise TimeoutError(
                        f"Message {item_hash} has been pending for too long."
                    )
            if status in [MessageStatus.REJECTED, MessageStatus.FORGOTTEN]:
                del self[item_hash]

        return _delete_if_rejected

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
        self.check_validity(MessageType.post, address, channel, post_content)
        resp, status = await self.session.create_post(
            post_content=post_content,
            post_type=post_type,
            ref=ref,
            address=address,
            channel=channel,
            inline=inline,
            storage_engine=storage_engine,
            sync=sync,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        asyncio.create_task(self.delete_if_rejected(resp.item_hash))
        return resp, status

    async def create_aggregate(
        self,
        key: str,
        content: Mapping[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(MessageType.aggregate, address, channel)
        resp, status = await self.session.create_aggregate(
            key=key,
            content=content,
            address=address,
            channel=channel,
            inline=inline,
            sync=sync,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        asyncio.create_task(self.delete_if_rejected(resp.item_hash))
        return resp, status

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
        self.check_validity(MessageType.store, address, channel, extra_fields)
        resp, status = await self.session.create_store(
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
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        asyncio.create_task(self.delete_if_rejected(resp.item_hash))
        return resp, status

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
        self.check_validity(
            MessageType.program, address, channel, dict(metadata) if metadata else None
        )
        resp, status = await self.session.create_program(
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
            allow_amend=allow_amend,
            internet=internet,
            aleph_api=aleph_api,
            encoding=encoding,
            volumes=volumes,
            subscriptions=subscriptions,
            metadata=metadata,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        asyncio.create_task(self.delete_if_rejected(resp.item_hash))
        return resp, status

    async def create_instance(
        self,
        rootfs: str,
        rootfs_size: int,
        rootfs_name: str,
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
        volumes: Optional[List[Mapping]] = None,
        volume_persistence: str = "host",
        ssh_keys: Optional[List[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(
            MessageType.instance, address, channel, dict(metadata) if metadata else None
        )
        resp, status = await self.session.create_instance(
            rootfs=rootfs,
            rootfs_size=rootfs_size,
            rootfs_name=rootfs_name,
            payment=payment,
            environment_variables=environment_variables,
            storage_engine=storage_engine,
            channel=channel,
            address=address,
            sync=sync,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            allow_amend=allow_amend,
            internet=internet,
            aleph_api=aleph_api,
            volumes=volumes,
            volume_persistence=volume_persistence,
            ssh_keys=ssh_keys,
            metadata=metadata,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self.add(resp)
        asyncio.create_task(self.delete_if_rejected(resp.item_hash))
        return resp, status

    async def forget(
        self,
        hashes: List[str],
        reason: Optional[str],
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        self.check_validity(MessageType.forget, address, channel)
        resp, status = await self.session.forget(
            hashes=hashes,
            reason=reason,
            storage_engine=storage_engine,
            channel=channel,
            address=address,
            sync=sync,
        )
        del self[resp.item_hash]
        return resp, status

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
        message, status, response = await self.session.submit(
            content=content,
            message_type=message_type,
            channel=channel,
            storage_engine=storage_engine,
            allow_inlining=allow_inlining,
            sync=sync,
            raise_on_rejected=raise_on_rejected,
        )
        if status in [MessageStatus.PROCESSED, MessageStatus.PENDING]:
            self.add(message)
        asyncio.create_task(self.delete_if_rejected(message.item_hash))
        return message, status, response
