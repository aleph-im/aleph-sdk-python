import datetime
import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import aiohttp
from aiohttp.client import _RequestContextManager
from aleph_message.models import Chain, ItemHash
from eth_account.messages import encode_defunct
from jwcrypto import jwk

from aleph.sdk.chains.solana import SOLAccount
from aleph.sdk.types import Account
from aleph.sdk.utils import (
    create_control_payload,
    create_vm_control_payload,
    sign_vm_control_payload,
    to_0x_hex,
)

logger = logging.getLogger(__name__)

_BACKUP_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


class VmOperation(str, Enum):
    STOP = "stop"
    REBOOT = "reboot"
    ERASE = "erase"
    BACKUP = "backup"
    RESTORE = "restore"
    REINSTALL = "reinstall"
    EXPIRE = "expire"
    RESCUE = "rescue"
    STREAM_LOGS = "stream_logs"

    def __str__(self) -> str:
        return self.value


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
        self,
        vm_id: ItemHash,
        operation: str,
        method: str = "POST",
        params: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[int], str]:
        url, header = await self._generate_header(
            vm_id=vm_id, operation=operation, method=method
        )

        try:
            request_kwargs: Dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": header,
            }
            if params:
                request_kwargs["params"] = params
            if json_data is not None:
                request_kwargs["json"] = json_data
            async with self.session.request(**request_kwargs) as response:
                response_text = await response.text()
                return response.status, response_text

        except aiohttp.ClientError as e:
            logger.error(f"HTTP error during operation {operation}: {str(e)}")
            return None, str(e)

    def operate(
        self, vm_id: ItemHash, operation: str, method: str = "POST"
    ) -> _RequestContextManager:
        """Request a CRN an operation for a VM (eg reboot, logs)

        This operation is authenticated via the user wallet.
        Use as an async context manager.
        e.g  `async with client.operate(vm_id=item_hash, operation="logs", method="GET") as response:`
        """

        async def authenticated_request():
            url, header = await self._generate_header(
                vm_id=vm_id, operation=operation, method=method
            )
            resp = await self.session._request(
                method=method, str_or_url=url, headers=header
            )
            return resp

        return _RequestContextManager(authenticated_request())

    async def get_logs(self, vm_id: ItemHash) -> AsyncGenerator[str, None]:
        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        payload = create_vm_control_payload(
            vm_id, VmOperation.STREAM_LOGS, method="get", domain=self.node_domain
        )
        signed_operation = sign_vm_control_payload(payload, self.ephemeral_key)
        path = payload["path"]
        ws_url = f"{self.node_url}{path}"

        async with self.session.ws_connect(
            ws_url,
            heartbeat=30,
            timeout=aiohttp.ClientWSTimeout(ws_close=10),
        ) as ws:
            auth_message = {
                "auth": {
                    "X-SignedPubKey": json.loads(self.pubkey_signature_header),
                    "X-SignedOperation": json.loads(signed_operation),
                }
            }
            await ws.send_json(auth_message)

            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    yield msg.data
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error("WebSocket error: %s", ws.exception() or "unknown")
                    break
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    logger.warning("WebSocket closed by server")
                    break

    async def start_instance(self, vm_id: ItemHash) -> Tuple[int, str]:
        return await self.notify_allocation(vm_id)

    async def stop_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, VmOperation.STOP)

    async def reboot_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, VmOperation.REBOOT)

    async def erase_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, VmOperation.ERASE)

    async def reinstall_instance(
        self, vm_id: ItemHash, erase_volumes: bool = True
    ) -> Tuple[Optional[int], str]:
        return await self.perform_operation(
            vm_id,
            VmOperation.REINSTALL,
            params={"erase_volumes": str(erase_volumes).lower()},
        )

    async def create_backup(
        self,
        vm_id: ItemHash,
        include_volumes: bool = False,
        skip_fsfreeze: bool = False,
    ) -> Tuple[Optional[int], str]:
        params: Optional[Dict[str, str]] = None
        if include_volumes or skip_fsfreeze:
            params = {}
            if include_volumes:
                params["include_volumes"] = "true"
            if skip_fsfreeze:
                params["skip_fsfreeze"] = "true"
        return await self.perform_operation(vm_id, VmOperation.BACKUP, params=params)

    async def get_backup(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, VmOperation.BACKUP, method="GET")

    async def delete_backup(
        self, vm_id: ItemHash, backup_id: str
    ) -> Tuple[Optional[int], str]:
        if not _BACKUP_ID_RE.match(backup_id):
            raise ValueError(
                f"Invalid backup_id {backup_id!r}: "
                "must contain only alphanumeric characters, hyphens, or underscores"
            )
        return await self.perform_operation(
            vm_id, f"backup/{backup_id}", method="DELETE"
        )

    async def get_restore_endpoint(self, vm_id: ItemHash) -> Tuple[str, Dict[str, str]]:
        """Return authenticated (url, headers) for a restore POST.

        Use this when you need control over the upload (e.g. progress
        tracking). For a simple restore, use restore_from_file instead.
        """
        return await self._generate_header(
            vm_id=vm_id, operation=VmOperation.RESTORE, method="POST"
        )

    async def restore_from_file(
        self, vm_id: ItemHash, rootfs_path: Union[str, Path]
    ) -> Tuple[Optional[int], str]:
        url, header = await self._generate_header(
            vm_id=vm_id, operation=VmOperation.RESTORE, method="POST"
        )
        rootfs_path = Path(rootfs_path)
        try:
            with open(rootfs_path, "rb") as f:
                data = aiohttp.FormData()
                data.add_field(
                    "rootfs",
                    f,
                    filename=rootfs_path.name,
                    content_type="application/octet-stream",
                )
                async with self.session.post(
                    url, headers=header, data=data
                ) as response:
                    text = await response.text()
                    return response.status, text
        except (aiohttp.ClientError, OSError) as e:
            logger.error(f"Error during restore: {e}")
            return None, str(e)

    async def restore_from_volume(
        self, vm_id: ItemHash, volume_ref: str
    ) -> Tuple[Optional[int], str]:
        return await self.perform_operation(
            vm_id,
            VmOperation.RESTORE,
            json_data={"volume_ref": volume_ref},
        )

    async def expire_instance(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, VmOperation.EXPIRE)

    async def enter_rescue(
        self, vm_id: ItemHash, item_hash: Optional[str] = None
    ) -> Tuple[Optional[int], str]:
        params = {"item_hash": item_hash} if item_hash else None
        return await self.perform_operation(vm_id, VmOperation.RESCUE, params=params)

    async def exit_rescue(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        return await self.perform_operation(vm_id, VmOperation.RESCUE, method="DELETE")

    async def notify_allocation(self, vm_id: ItemHash) -> Tuple[int, str]:
        json_data = {"instance": vm_id}

        async with self.session.post(
            f"{self.node_url}/control/allocation/notify", json=json_data
        ) as session:
            form_response_text = await session.text()

            return session.status, form_response_text

    async def reserve_resources(
        self, instance_content: Dict[str, Any]
    ) -> Tuple[Optional[int], str]:
        """Pre-check CRN capacity for an instance before creating it.

        Sends the instance content to the CRN for admission control.
        Returns 200 with {"status": "reserved", "expires": ...} if resources
        are available, 503 if the CRN cannot fit the request.
        """
        path = "/control/reserve_resources"
        payload = create_control_payload(
            path=path, domain=self.node_domain, method="POST"
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

        try:
            async with self.session.post(
                f"{self.node_url}{path}", headers=headers, json=instance_content
            ) as resp:
                return resp.status, await resp.text()
        except aiohttp.ClientError as e:
            logger.error("HTTP error during reserve_resources: %s", e)
            return None, str(e)

    async def manage_instance(
        self, vm_id: ItemHash, operations: List[Union[VmOperation, str]]
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
