import base64
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import aiohttp
from aleph_message.models import ItemHash

from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.types import Account, SEVMeasurement
from aleph.sdk.utils import (
    compute_confidential_measure,
    encrypt_secret_table,
    get_vm_measure,
    make_packet_header,
    make_secret_table,
    run_in_subprocess,
)

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
        """
        Get platform confidential certificate
        """

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
        self, certificate_prefix: str, platform_certificate_path: Path, policy: int
    ) -> Path:
        """
        Create new confidential session
        """

        current_path = Path().cwd()
        args = [
            "session",
            "--name",
            certificate_prefix,
            str(platform_certificate_path),
            str(policy),
        ]
        try:
            # TODO: Check command result
            await self.sevctl_cmd(*args)
            return current_path
        except Exception as e:
            raise ValueError(f"Session creation have failed, reason: {str(e)}")

    async def initialize(self, vm_id: ItemHash, session: Path, godh: Path) -> str:
        """
        Initialize Confidential VM negociation passing the needed session files
        """

        session_file = session.read_bytes()
        godh_file = godh.read_bytes()
        params = {
            "session": session_file,
            "godh": godh_file,
        }
        return await self.perform_confidential_operation(
            vm_id, "confidential/initialize", params=params
        )

    async def measurement(self, vm_id: ItemHash) -> SEVMeasurement:
        """
        Fetch VM confidential measurement
        """

        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        status, text = await self.perform_operation(
            vm_id, "confidential/measurement", method="GET"
        )
        sev_measurement = SEVMeasurement.parse_raw(text)
        return sev_measurement

    async def validate_measure(
        self, sev_data: SEVMeasurement, tik_path: Path, firmware_hash: str
    ) -> bool:
        """
        Validate VM confidential measurement
        """

        tik = tik_path.read_bytes()
        vm_measure, nonce = get_vm_measure(sev_data)

        expected_measure = compute_confidential_measure(
            sev_info=sev_data.sev_info,
            tik=tik,
            expected_hash=firmware_hash,
            nonce=nonce,
        ).digest()
        return expected_measure == vm_measure

    async def build_secret(
        self, tek_path: Path, tik_path: Path, sev_data: SEVMeasurement, secret: str
    ) -> Tuple[str, str]:
        """
        Build disk secret to be injected on the confidential VM
        """

        tek = tek_path.read_bytes()
        tik = tik_path.read_bytes()

        vm_measure, _ = get_vm_measure(sev_data)

        iv = os.urandom(16)
        secret_table = make_secret_table(secret)
        encrypted_secret_table = encrypt_secret_table(
            secret_table=secret_table, tek=tek, iv=iv
        )

        packet_header = make_packet_header(
            vm_measure=vm_measure,
            encrypted_secret_table=encrypted_secret_table,
            secret_table_size=len(secret_table),
            tik=tik,
            iv=iv,
        )

        encoded_packet_header = base64.b64encode(packet_header).decode()
        encoded_secret = base64.b64encode(encrypted_secret_table).decode()

        return encoded_packet_header, encoded_secret

    async def inject_secret(
        self, vm_id: ItemHash, packet_header: str, secret: str
    ) -> Dict:
        """
        Send the secret by the encrypted channel to boot up the VM
        """

        params = {
            "packet_header": packet_header,
            "secret": secret,
        }
        text = await self.perform_confidential_operation(
            vm_id, "confidential/inject_secret", json=params
        )

        return json.loads(text)

    async def perform_confidential_operation(
        self,
        vm_id: ItemHash,
        operation: str,
        params: Optional[Dict[str, Any]] = None,
        json=None,
    ) -> str:
        """
        Send confidential operations to the CRN passing the auth headers on each request
        """

        if not self.pubkey_signature_header:
            self.pubkey_signature_header = (
                await self._generate_pubkey_signature_header()
            )

        url, header = await self._generate_header(
            vm_id=vm_id, operation=operation, method="post"
        )

        try:
            async with self.session.post(
                url, headers=header, data=params, json=json
            ) as response:
                response.raise_for_status()
                response_text = await response.text()
                return response_text

        except aiohttp.ClientError as e:
            raise ValueError(f"HTTP error during operation {operation}: {str(e)}")

    async def sevctl_cmd(self, *args) -> bytes:
        """
        Execute `sevctl` command with given arguments
        """

        return await run_in_subprocess(
            [str(self.sevctl_path), *args],
            check=True,
        )
