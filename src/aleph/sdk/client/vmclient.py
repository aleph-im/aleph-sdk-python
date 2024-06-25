import datetime
import json
import logging
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from aleph_message.models import ItemHash
from eth_account.messages import encode_defunct
from jwcrypto import jwk
from jwcrypto.jwa import JWA

from aleph.sdk.types import Account
from aleph.sdk.utils import to_0x_hex

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
        self.node_url = node_url
        self.pubkey_payload = self._generate_pubkey_payload()
        self.pubkey_signature_header = ""
        self.session = session or aiohttp.ClientSession()

    def _generate_pubkey_payload(self) -> Dict[str, Any]:
        return {
            "pubkey": json.loads(self.ephemeral_key.export_public()),
            "alg": "ECDSA",
            "domain": urlparse(self.node_url).netloc,
            "address": self.account.get_address(),
            "expires": (
                datetime.datetime.utcnow() + datetime.timedelta(days=1)
            ).isoformat()
            + "Z",
        }

    async def _generate_pubkey_signature_header(self) -> str:
        pubkey_payload = json.dumps(self.pubkey_payload).encode("utf-8").hex()
        signable_message = encode_defunct(hexstr=pubkey_payload)
        buffer_to_sign = signable_message.body

        signed_message = await self.account.sign_raw(buffer_to_sign)
        pubkey_signature = to_0x_hex(signed_message)

        return json.dumps(
            {
                "sender": self.account.get_address(),
                "payload": pubkey_payload,
                "signature": pubkey_signature,
                "content": {"domain": urlparse(self.node_url).netloc},
            }
        )

    def create_payload(self, vm_id: ItemHash, operation: str) -> Dict[str, str]:
        path = f"/control/machine/{vm_id}/{operation}"
        payload = {
            "time": datetime.datetime.utcnow().isoformat() + "Z",
            "method": "POST",
            "path": path,
        }
        return payload

    def sign_payload(self, payload: Dict[str, str], ephemeral_key) -> str:
        payload_as_bytes = json.dumps(payload).encode("utf-8")
        payload_signature = JWA.signing_alg("ES256").sign(
            ephemeral_key, payload_as_bytes
        )
        signed_operation = json.dumps(
            {
                "payload": payload_as_bytes.hex(),
                "signature": payload_signature.hex(),
            }
        )
        return signed_operation

    async def _generate_header(
        self, vm_id: ItemHash, operation: str
    ) -> Tuple[str, Dict[str, str]]:
        payload = self.create_payload(vm_id, operation)
        signed_operation = self.sign_payload(payload, self.ephemeral_key)

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

    async def perform_operation(
        self, vm_id: ItemHash, operation: str
    ) -> Tuple[Optional[int], str]:
        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        url, header = await self._generate_header(vm_id=vm_id, operation=operation)

        try:
            async with self.session.post(url, headers=header) as response:
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

        payload = self.create_payload(vm_id, "logs")
        signed_operation = self.sign_payload(payload, self.ephemeral_key)
        path = payload["path"]
        ws_url = f"{self.node_url}{path}"

        async with self.session.ws_connect(ws_url) as ws:
            auth_message = {
                "auth": {
                    "X-SignedPubKey": self.pubkey_signature_header,
                    "X-SignedOperation": signed_operation,
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

    async def manage_instance(self, vm_id: ItemHash, operations: List[str]):
        for operation in operations:
            status, response = await self.perform_operation(vm_id, operation)
            if status != 200:
                return status, response
        return

    async def close(self):
        await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()
