# Implementation of an Aleph Domain Node
# A Domain Node is a queryable proxy for Aleph Messages that are stored in a
# database cache and/or in the Aleph network. It synchronizes with the network
# on a subset of the messages by listening to the network and storing the
# messages in the cache. The user may define the subset by specifying a
# channels, tags, senders, chains, message types, and/or a time window.
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import (
    Optional,
    List,
    Dict,
    Iterable,
    Union,
    AsyncIterable,
    Type,
    Tuple,
    Mapping,
    Any,
)

from aleph_message import MessagesResponse
from aleph_message.models import Chain, MessageType, AlephMessage
from aleph_message.models.program import Encoding
from aleph_message.status import MessageStatus

from aleph.sdk import AlephClient
from aleph.sdk.interface import AuthenticatedAlephClientInterface
from aleph.sdk.cache import MessageCache
from aleph.sdk.types import GenericMessage, StorageEnum


class DomainNode(MessageCache, AuthenticatedAlephClientInterface):
    def __init__(
        self,
        session: AlephClient,
        channels: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        senders: Optional[List[str]] = None,
        chains: Optional[List[Chain]] = None,
        message_types: Optional[List[MessageType]] = None,
    ):
        self.session = session
        self.channels = channels
        self.tags = tags
        self.senders = senders
        self.chains = chains
        self.message_types = message_types

        # synchronize with past messages
        resp = asyncio.get_event_loop().run_until_complete(
            self.session.get_messages(
                channels=self.channels,
                tags=self.tags,
                addresses=self.senders,
                chains=self.chains,
                message_types=self.message_types,
            )
        )
        # start listening to the network and storing messages in the cache
        asyncio.get_event_loop().create_task(self.listen_to(
            self.session.watch_messages(
                channels=self.channels,
                tags=self.tags,
                addresses=self.senders,
                chains=self.chains,
                message_type=self.message_types,
            )
        ))

    async def fetch_aggregate(
        self, address: str, key: str, limit: int = 100
    ) -> Dict[str, Dict]:
        """
        Fetch an aggregate by address and key from the cache.
        """
        return await self.cache.fetch_aggregate(address, key, limit)

    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None, limit: int = 100
    ) -> Dict[str, Dict]:
        pass

    async def get_posts(
        self,
        pagination: int = 200,
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
    ) -> Dict[str, Dict]:
        pass

    async def download_file(self, file_hash: str) -> bytes:
        pass

    async def get_messages(
        self,
        pagination: int = 200,
        page: int = 1,
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
        ignore_invalid_messages: bool = True,
        invalid_messages_log_level: int = logging.NOTSET,
    ) -> MessagesResponse:
        pass

    async def get_message(
        self,
        item_hash: str,
        message_type: Optional[Type[GenericMessage]] = None,
        channel: Optional[str] = None,
    ) -> GenericMessage:
        pass

    async def watch_messages(
        self,
        message_type: Optional[MessageType] = None,
        content_types: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
    ) -> AsyncIterable[AlephMessage]:
        pass

    async def ipfs_push(self, content: Mapping) -> str:
        pass

    async def storage_push(self, content: Mapping) -> str:
        pass

    async def ipfs_push_file(self, file_content: Union[str, bytes]) -> str:
        pass

    async def storage_push_file(self, file_content: Union[str, bytes]) -> str:
        pass

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
        pass

    async def create_aggregate(
        self,
        key: str,
        content: Mapping[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        pass

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
        pass

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
        pass

    async def forget(
        self,
        hashes: List[str],
        reason: Optional[str],
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        pass

    async def submit(
        self,
        content: Dict[str, Any],
        message_type: MessageType,
        channel: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        allow_inlining: bool = True,
        sync: bool = False,
    ) -> Tuple[AlephMessage, MessageStatus]:
        pass
