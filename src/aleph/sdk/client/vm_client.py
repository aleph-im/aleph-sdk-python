import datetime
import json
import logging
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from aleph_message.models import Chain, ItemHash
from eth_account.messages import encode_defunct
from jwcrypto import jwk

from aleph.sdk.chains.solana import SOLAccount
from aleph.sdk.types import Account
from aleph.sdk.utils import (
    create_vm_control_payload,
    sign_vm_control_payload,
    to_0x_hex,
)

logger = logging.getLogger(__name__)


class VmClient:
    account: Account
    ephemeral_key: jwk.JWK
    node_url: str
    pubkey_payload: Dict[str, Any]
    pubkey_signature_header: str
    session: aiohttp.ClientSession

    def __init__(
        self,
        account: Account,
        node_url: str = "",
        session: Optional[aiohttp.ClientSession] = None,
    ):
        self.account = account
        self.ephemeral_key = jwk.JWK.generate(kty="EC", crv="P-256")
        self.node_url = node_url.rstrip("/")
        self.pubkey_payload = self._generate_pubkey_payload(
            Chain.SOL if isinstance(account, SOLAccount) else Chain.ETH
        )
        self.pubkey_signature_header = ""
        self.session = session or aiohttp.ClientSession()

    def _generate_pubkey_payload(self, chain: Chain = Chain.ETH) -> Dict[str, Any]:
        return {
            "pubkey": json.loads(self.ephemeral_key.export_public()),
            "alg": "ECDSA",
            "domain": self.node_domain,
            "address": self.account.get_address(),
            "expires": (
                datetime.datetime.utcnow() + datetime.timedelta(days=1)
            ).isoformat()
            + "Z",
            "chain": chain.value,
        }

    async def _generate_pubkey_signature_header(self) -> str:
        pubkey_payload = json.dumps(self.pubkey_payload).encode("utf-8").hex()
        if isinstance(self.account, SOLAccount):
            buffer_to_sign = bytes(pubkey_payload, encoding="utf-8")
        else:
            signable_message = encode_defunct(hexstr=pubkey_payload)
            buffer_to_sign = signable_message.body

        signed_message = await self.account.sign_raw(buffer_to_sign)
        pubkey_signature = to_0x_hex(signed_message)

        return json.dumps(
            {
                "sender": self.account.get_address(),
                "payload": pubkey_payload,
                "signature": pubkey_signature,
                "content": {"domain": self.node_domain},
            }
        )

    async def _generate_header(
        self, vm_id: ItemHash, operation: str, method: str
    ) -> Tuple[str, Dict[str, str]]:
        payload = create_vm_control_payload(
            vm_id, operation, domain=self.node_domain, method=method
        )
        signed_operation = sign_vm_control_payload(payload, self.ephemeral_key)

        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        headers = {
            "X-SignedPubKey": self.pubkey_signature_header,
            "X-SignedOperation": signed_operation,
        }

        path = payload["path"]
        return f"{self.node_url}{path}", headers

    @property
    def node_domain(self) -> str:
        domain = urlparse(self.node_url).hostname
        if not domain:
            raise Exception("Could not parse node domain")
        return domain

    async def perform_operation(
        self, vm_id: ItemHash, operation: str, method: str = "POST"
    ) -> Tuple[Optional[int], str]:
        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        url, header = await self._generate_header(
            vm_id=vm_id, operation=operation, method=method
        )

        try:
            async with self.session.request(
                method=method, url=url, headers=header
            ) as response:
                response_text = await response.text()
                return response.status, response_text

        except aiohttp.ClientError as e:
            logger.error(f"HTTP error during operation {operation}: {str(e)}")
            return None, str(e)

    async def get_logs(self, vm_id: ItemHash) -> AsyncGenerator[str, None]:
        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        payload = create_vm_control_payload(
            vm_id, "stream_logs", method="get", domain=self.node_domain
        )
        signed_operation = sign_vm_control_payload(payload, self.ephemeral_key)
        path = payload["path"]
        ws_url = f"{self.node_url}{path}"

        async with self.session.ws_connect(ws_url) as ws:
            auth_message = {
                "auth": {
                    "X-SignedPubKey": json.loads(self.pubkey_signature_header),
                    "X-SignedOperation": json.loads(signed_operation),
                }
            }
            await ws.send_json(auth_message)

            async for msg in ws:  # msg is of type aiohttp.WSMessage
                if msg.type == aiohttp.WSMsgType.TEXT:
                    yield msg.data
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break

    async def start_instance(self, vm_id: ItemHash) -> Tuple[int, str]:
        return await self.notify_allocation(vm_id)

    async def stop_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, "stop")

    async def reboot_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, "reboot")

    async def erase_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, "erase")

    async def expire_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, "expire")

    async def notify_allocation(self, vm_id: ItemHash) -> Tuple[int, str]:
        json_data = {"instance": vm_id}

        async with self.session.post(
            f"{self.node_url}/control/allocation/notify", json=json_data
        ) as session:
            form_response_text = await session.text()

            return session.status, form_response_text

    async def manage_instance(
        self, vm_id: ItemHash, operations: List[str]
    ) -> Tuple[int, str]:
        for operation in operations:
            status, response = await self.perform_operation(vm_id, operation)
            if status != 200 and status:
                return status, response
        return 200, "All operations completed successfully"

    async def close(self):
        await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()
