# Implementation of an Aleph Domain Node
# A Domain Node is a queryable proxy for Aleph Messages that are stored in a
# database cache and/or in the Aleph network. It synchronizes with the network
# on a subset of the messages by listening to the network and storing the
# messages in the cache. The user may define the subset by specifying a
# channels, tags, senders, chains, message types, and/or a time window.
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from aleph_message.models import AlephMessage, Chain, MessageType
from aleph_message.models.program import Encoding
from aleph_message.status import MessageStatus

from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.cache import MessageCache
from aleph.sdk.base import AuthenticatedAlephClientBase
from aleph.sdk.types import StorageEnum


class DomainNode(MessageCache, AuthenticatedAlephClientBase):
    def __init__(
        self,
        session: AuthenticatedAlephClient,
        channels: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[Chain]] = None,
        message_type: Optional[MessageType] = None,
    ):
        super().__init__()
        self.session = session
        self.channels = channels
        self.tags = tags
        self.addresses = addresses
        self.chains = chains
        self.message_type = message_type

        # start listening to the network and storing messages in the cache
        asyncio.get_event_loop().create_task(
            self.listen_to(
                self.session.watch_messages(
                    channels=self.channels,
                    tags=self.tags,
                    addresses=self.addresses,
                    chains=self.chains,
                    message_type=self.message_type,
                )
            )
        )

        # synchronize with past messages
        asyncio.get_event_loop().run_until_complete(
            self.synchronize(
                channels=self.channels,
                tags=self.tags,
                addresses=self.addresses,
                chains=self.chains,
                message_type=self.message_type,
            )
        )

    async def synchronize(
        self,
        channels: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[Chain]] = None,
        message_type: Optional[MessageType] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
    ):
        """
        Synchronize with past messages.
        """
        chunk_size = 200
        messages = []
        async for message in self.session.get_messages_iterator(
            channels=channels,
            tags=tags,
            addresses=addresses,
            chains=chains,
            message_type=message_type,
            start_date=start_date,
            end_date=end_date,
        ):
            messages.append(message)
            if len(messages) >= chunk_size:
                self.add(messages)
                messages = []
        if messages:
            self.add(messages)

    async def download_file(self, file_hash: str) -> bytes:
        """
        Opens a file that has been locally stored by its hash.
        """
        try:
            with open(self._file_path(file_hash), "rb") as f:
                return f.read()
        except FileNotFoundError:
            file = await self.session.download_file(file_hash)
            with open(self._file_path(file_hash), "wb") as f:
                f.write(file)
            return file

    def _file_path(self, file_hash: str) -> Path:
        # TODO: Make this configurable (and not be an ugly hack)
        return Path("cache", "files", file_hash)

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
        # TODO: This can cause inconsistencies, if the message is rejected by the aleph node
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self[resp.item_hash] = resp
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
        resp, status = await self.session.create_aggregate(
            key=key,
            content=content,
            address=address,
            channel=channel,
            inline=inline,
            sync=sync,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self[resp.item_hash] = resp
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
            self[resp.item_hash] = resp
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
        encoding: Encoding = Encoding.zip,
        volumes: Optional[List[Mapping]] = None,
        subscriptions: Optional[List[Mapping]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[AlephMessage, MessageStatus]:
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
            encoding=encoding,
            volumes=volumes,
            subscriptions=subscriptions,
            metadata=metadata,
        )
        if status in [MessageStatus.PENDING, MessageStatus.PROCESSED]:
            self[resp.item_hash] = resp
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
    ) -> Tuple[AlephMessage, MessageStatus]:
        resp, status = await self.session.submit(
            content=content,
            message_type=message_type,
            channel=channel,
            storage_engine=storage_engine,
            allow_inlining=allow_inlining,
            sync=sync,
        )
        # TODO: this can cause inconsistencies if the message is dropped
        if status in [MessageStatus.PROCESSED, MessageStatus.PENDING]:
            self[resp.item_hash] = resp["message"]
        return resp, status
