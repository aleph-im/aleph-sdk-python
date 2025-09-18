from typing import Optional

import aiohttp
from aiohttp import ClientResponseError
from aleph_message.models import Chain

from aleph.sdk.conf import settings
from aleph.sdk.query.filters import PostFilter
from aleph.sdk.query.responses import Post, PostsResponse
from aleph.sdk.types import Voucher, VoucherMetadata


class Vouchers:
    """
    This service is made to fetch voucher (SOL / EVM)
    """

    def __init__(self, client):
        self._client = client

    # Utils
    def _resolve_address(self, address: str) -> str:
        return address  # Not Authenticated client so address need to be given

    async def _fetch_voucher_update(self):
        """
        Fetch the latest EVM voucher update (unfiltered).
        """

        post_filter = PostFilter(
            types=["vouchers-update"], addresses=[settings.VOUCHER_ORIGIN_ADDRESS]
        )
        vouchers_post: PostsResponse = await self._client.get_posts(
            post_filter=post_filter, page_size=1
        )

        if not vouchers_post.posts:
            return []

        message_post: Post = vouchers_post.posts[0]

        nft_vouchers = message_post.content.get("nft_vouchers", {})
        return list(nft_vouchers.items())  # [(voucher_id, voucher_data)]

    async def _fetch_solana_voucher_list(self):
        """
        Fetch full Solana voucher registry (unfiltered).
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(settings.VOUCHER_SOL_REGISTRY) as resp:
                    resp.raise_for_status()
                    return await resp.json()
        except ClientResponseError:
            return {}

    async def fetch_voucher_metadata(
        self, metadata_id: str
    ) -> Optional[VoucherMetadata]:
        """
        Fetch metadata for a given voucher.
        """
        url = f"https://claim.twentysix.cloud/sbt/metadata/{metadata_id}.json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    return VoucherMetadata.model_validate(data)
        except ClientResponseError:
            return None

    async def get_solana_vouchers(self, address: str) -> list[Voucher]:
        """
        Fetch Solana vouchers for a specific address.
        """
        resolved_address = self._resolve_address(address=address)
        vouchers: list[Voucher] = []

        registry_data = await self._fetch_solana_voucher_list()

        claimed_tickets = registry_data.get("claimed_tickets", {})
        batches = registry_data.get("batches", {})

        for ticket_hash, ticket_data in claimed_tickets.items():
            claimer = ticket_data.get("claimer")
            if claimer != resolved_address:
                continue

            batch_id = ticket_data.get("batch_id")
            metadata_id = None

            if str(batch_id) in batches:
                metadata_id = batches[str(batch_id)].get("metadata_id")

            if metadata_id:
                metadata = await self.fetch_voucher_metadata(metadata_id)
                if metadata:
                    voucher = Voucher(
                        id=ticket_hash,
                        metadata_id=metadata_id,
                        name=metadata.name,
                        description=metadata.description,
                        external_url=metadata.external_url,
                        image=metadata.image,
                        icon=metadata.icon,
                        attributes=metadata.attributes,
                    )
                    vouchers.append(voucher)

        return vouchers

    async def get_evm_vouchers(self, address: str) -> list[Voucher]:
        """
        Retrieve vouchers specific to EVM chains for a specific address.
        """
        resolved_address = self._resolve_address(address=address)
        vouchers: list[Voucher] = []

        nft_vouchers = await self._fetch_voucher_update()
        for voucher_id, voucher_data in nft_vouchers:
            if voucher_data.get("claimer") != resolved_address:
                continue

            metadata_id = voucher_data.get("metadata_id")
            metadata = await self.fetch_voucher_metadata(metadata_id)
            if not metadata:
                continue

            voucher = Voucher(
                id=voucher_id,
                metadata_id=metadata_id,
                name=metadata.name,
                description=metadata.description,
                external_url=metadata.external_url,
                image=metadata.image,
                icon=metadata.icon,
                attributes=metadata.attributes,
            )
            vouchers.append(voucher)
        return vouchers

    async def fetch_vouchers_by_chain(self, chain: Chain, address: str):
        if chain == Chain.SOL:
            return await self.get_solana_vouchers(address=address)
        else:
            return await self.get_evm_vouchers(address=address)

    async def get_vouchers(self, address: str) -> list[Voucher]:
        """
        Retrieve all vouchers for the account / specific adress, across EVM and Solana chains.
        """
        vouchers = []

        # Get EVM vouchers
        if address.startswith("0x") and len(address) == 42:
            evm_vouchers = await self.get_evm_vouchers(address=address)
            vouchers.extend(evm_vouchers)
        else:
            # Get Solana vouchers
            solana_vouchers = await self.get_solana_vouchers(address=address)
            vouchers.extend(solana_vouchers)

        return vouchers
