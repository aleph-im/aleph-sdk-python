import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import aiohttp
from aleph_message.models import ItemHash

from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.types import Account
from aleph.sdk.utils import run_in_subprocess

logger = logging.getLogger(__name__)


class VmConfidentialClient(VmClient):
    sevctl_path: Path

    def __init__(
        self,
        account: Account,
        sevctl_path: Path,
        node_url: str = "",
        session: Optional[aiohttp.ClientSession] = None,
    ):
        super().__init__(account, node_url, session)
        self.sevctl_path = sevctl_path

    async def get_certificates(self) -> Tuple[Optional[int], str]:
        url = f"{self.node_url}/about/certificates"
        try:
            async with self.session.get(url) as response:
                data = await response.read()
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    tmp_file.write(data)
                    return response.status, tmp_file.name

        except aiohttp.ClientError as e:
            logger.error(
                f"HTTP error getting node certificates on {self.node_url}: {str(e)}"
            )
            return None, str(e)

    async def create_session(
        self, vm_id: ItemHash, certificate_path: Path, policy: int
    ) -> Path:
        current_path = Path().cwd()
        args = [
            "session",
            "--name",
            str(vm_id),
            str(certificate_path),
            str(policy),
        ]
        try:
            # TODO: Check command result
            await self.sevctl_cmd(*args)
            return current_path
        except Exception as e:
            raise ValueError(f"Session creation have failed, reason: {str(e)}")

    async def initialize(
        self, vm_id: ItemHash, session: Path, godh: Path
    ) -> Tuple[Optional[int], str]:
        session_file = session.read_bytes()
        godh_file = godh.read_bytes()
        params = {
            "session": session_file,
            "godh": godh_file,
        }
        return await self.perform_confidential_operation(
            vm_id, "confidential/initialize", params=params
        )

    async def measurement(self, vm_id: ItemHash) -> Tuple[Optional[int], str]:
        status, text = await self.perform_confidential_operation(
            vm_id, "confidential/measurement"
        )
        if status:
            response = json.loads(text)
            return status, response

        return status, text

    async def validate_measurement(self, vm_id: ItemHash) -> bool:
        # TODO: Implement measurement validation
        return True

    async def build_secret(
        self, tek_path: Path, tik_path: Path, measurement: str, secret: str
    ) -> Tuple[Path, Path]:
        current_path = Path().cwd()
        secret_header_path = current_path / "secret_header.bin"
        secret_payload_path = current_path / "secret_payload.bin"
        args = [
            "secret",
            "build",
            "--tik",
            str(tik_path),
            "--tek",
            str(tek_path),
            "--launch-measure-blob",
            measurement,
            "--secret",
            secret,
            str(secret_header_path),
            str(secret_payload_path),
        ]
        try:
            # TODO: Check command result
            await self.sevctl_cmd(*args)
            return secret_header_path, secret_payload_path
        except Exception as e:
            raise ValueError(f"Secret building have failed, reason: {str(e)}")

    async def inject_secret(
        self, vm_id: ItemHash, packed_header: str, secret: str
    ) -> Tuple[Optional[int], str]:
        params = {
            "packed_header": packed_header,
            "secret": secret,
        }
        status, text = await self.perform_confidential_operation(
            vm_id, "confidential/inject_secret", params=params
        )

        if status:
            response = json.loads(text)
            return status, response

        return status, text

    async def perform_confidential_operation(
        self, vm_id: ItemHash, operation: str, params: Optional[Dict[str, Any]] = None
    ) -> Tuple[Optional[int], str]:
        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        url, header = await self._generate_header(vm_id=vm_id, operation=operation)

        try:
            async with self.session.post(url, headers=header, data=params) as response:
                response_text = await response.text()
                return response.status, response_text

        except aiohttp.ClientError as e:
            logger.error(f"HTTP error during operation {operation}: {str(e)}")
            return None, str(e)

    async def sevctl_cmd(self, *args) -> bytes:
        return await run_in_subprocess(
            [str(self.sevctl_path), *args],
            check=True,
        )
