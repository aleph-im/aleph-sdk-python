import asyncio
import base64
import errno
import hashlib
import hmac
import json
import logging
import os
import subprocess
from datetime import date, datetime, time
from enum import Enum
from pathlib import Path
from shutil import make_archive
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    Type,
    TypeVar,
    Union,
    get_args,
)
from uuid import UUID
from zipfile import BadZipFile, ZipFile

from aleph_message.models import ItemHash, MessageType
from aleph_message.models.execution.program import Encoding
from aleph_message.models.execution.volume import MachineVolume
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from jwcrypto.jwa import JWA
from pydantic.json import pydantic_encoder

from aleph.sdk.conf import settings
from aleph.sdk.types import GenericMessage, SEVInfo, SEVMeasurement

logger = logging.getLogger(__name__)

try:
    import magic
except ImportError:
    logger.info("Could not import library 'magic', MIME type detection disabled")
    magic = None  # type:ignore


def try_open_zip(path: Path) -> None:
    """Try opening a zip to check if it is valid"""
    assert path.is_file()
    with open(path, "rb") as archive_file:
        with ZipFile(archive_file, "r") as archive:
            if not archive.namelist():
                raise BadZipFile("No file in the archive.")


def create_archive(path: Path) -> Tuple[Path, Encoding]:
    """Create a zip archive from a directory"""
    if os.path.isdir(path):
        if settings.CODE_USES_SQUASHFS:
            logger.debug("Creating squashfs archive...")
            archive_path = Path(f"{path}.squashfs")
            os.system(f"mksquashfs {path} {archive_path} -noappend")
            assert archive_path.is_file()
            return archive_path, Encoding.squashfs
        else:
            logger.debug("Creating zip archive...")
            make_archive(str(path), "zip", path)
            archive_path = Path(f"{path}.zip")
            return archive_path, Encoding.zip
    elif os.path.isfile(path):
        if path.suffix == ".squashfs" or (
            magic and magic.from_file(path).startswith("Squashfs filesystem")
        ):
            return path, Encoding.squashfs
        else:
            try_open_zip(Path(path))
            return path, Encoding.zip
    else:
        raise FileNotFoundError("No file or directory to create the archive from")


def get_message_type_value(message_type: Type[GenericMessage]) -> MessageType:
    """Returns the value of the 'type' field of a message type class."""
    type_literal = message_type.__annotations__["type"]
    return type_literal.__args__[0]  # Get the value from a Literal


def check_unix_socket_valid(unix_socket_path: str) -> bool:
    """Check that a unix socket exists at the given path, or raise a FileNotFoundError."""
    path = Path(unix_socket_path)
    if not path.exists():
        raise FileNotFoundError(
            errno.ENOENT, os.strerror(errno.ENOENT), unix_socket_path
        )
    if not path.is_socket():
        raise FileNotFoundError(
            errno.ENOTSOCK,
            os.strerror(errno.ENOENT),
            unix_socket_path,
        )
    return True


T = TypeVar("T", str, bytes, covariant=True)
U = TypeVar("U", str, bytes, contravariant=True)


class AsyncReadable(Protocol[T]):
    async def read(self, n: int = -1) -> T: ...


class Writable(Protocol[U]):
    def write(self, buffer: U) -> int: ...


async def copy_async_readable_to_buffer(
    readable: AsyncReadable[T], buffer: Writable[T], chunk_size: int
):
    while True:
        chunk = await readable.read(chunk_size)
        if not chunk:
            break
        buffer.write(chunk)


def enum_as_str(obj: Optional[Union[str, Enum]]) -> Optional[str]:
    """Returns the value of an Enum, or the string itself when passing a string.

    Python 3.11 adds a new formatting of string enums.
    `str(MyEnum.value)` becomes `MyEnum.value` instead of `value`.
    """
    if not obj:
        return None
    if not isinstance(obj, str):
        raise TypeError(f"Unsupported enum type: {type(obj)}")

    if isinstance(obj, Enum):
        return obj.value

    return obj


def serialize_list(values: Optional[Iterable[str]]) -> Optional[str]:
    if values:
        return ",".join(values)
    else:
        return None


def _date_field_to_timestamp(date: Optional[Union[datetime, float]]) -> Optional[str]:
    if date is None:
        return None
    elif isinstance(date, float):
        return str(date)
    elif hasattr(date, "timestamp"):
        return str(date.timestamp())
    else:
        raise TypeError(f"Invalid type: `{type(date)}`")


def extended_json_encoder(obj: Any) -> Any:
    """
    Extended JSON encoder for dumping objects that contain pydantic models and datetime objects.
    """
    if isinstance(obj, datetime):
        return obj.timestamp()
    elif isinstance(obj, date):
        return obj.toordinal()
    elif isinstance(obj, time):
        return obj.hour * 3600 + obj.minute * 60 + obj.second + obj.microsecond / 1e6
    else:
        return pydantic_encoder(obj)


def parse_volume(volume_dict: Union[Mapping, MachineVolume]) -> MachineVolume:
    # Python 3.9 does not support `isinstance(volume_dict, MachineVolume)`,
    # so we need to iterate over all types.
    if any(
        isinstance(volume_dict, volume_type) for volume_type in get_args(MachineVolume)
    ):
        return volume_dict
    for volume_type in get_args(MachineVolume):
        try:
            return volume_type.parse_obj(volume_dict)
        except ValueError:
            continue
    else:
        raise ValueError(f"Could not parse volume: {volume_dict}")


def compute_sha256(s: str) -> str:
    """Compute the SHA256 hash of a string."""
    return hashlib.sha256(s.encode()).hexdigest()


def to_0x_hex(b: bytes) -> str:
    return "0x" + bytes.hex(b)


def bytes_from_hex(hex_string: str) -> bytes:
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    hex_string = bytes.fromhex(hex_string)
    return hex_string


def create_vm_control_payload(
    vm_id: ItemHash, operation: str, domain: str, method: str
) -> Dict[str, str]:
    path = f"/control/machine/{vm_id}/{operation}"
    payload = {
        "time": datetime.utcnow().isoformat() + "Z",
        "method": method.upper(),
        "path": path,
        "domain": domain,
    }
    return payload


def sign_vm_control_payload(payload: Dict[str, str], ephemeral_key) -> str:
    payload_as_bytes = json.dumps(payload).encode("utf-8")
    payload_signature = JWA.signing_alg("ES256").sign(ephemeral_key, payload_as_bytes)
    signed_operation = json.dumps(
        {
            "payload": payload_as_bytes.hex(),
            "signature": payload_signature.hex(),
        }
    )
    return signed_operation


async def run_in_subprocess(
    command: List[str], check: bool = True, stdin_input: Optional[bytes] = None
) -> bytes:
    """Run the specified command in a subprocess, returns the stdout of the process."""
    logger.debug(f"command: {' '.join(command)}")

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate(input=stdin_input)

    if check and process.returncode:
        logger.error(
            f"Command failed with error code {process.returncode}:\n"
            f"    stdin = {stdin_input!r}\n"
            f"    command = {command}\n"
            f"    stdout = {stderr!r}"
        )
        raise subprocess.CalledProcessError(
            process.returncode, str(command), stderr.decode()
        )

    return stdout


def get_vm_measure(sev_data: SEVMeasurement) -> Tuple[bytes, bytes]:
    launch_measure = base64.b64decode(sev_data.launch_measure)
    vm_measure = launch_measure[0:32]
    nonce = launch_measure[32:48]
    return vm_measure, nonce


def calculate_firmware_hash(firmware_path: Path) -> str:
    """Calculate the hash of the firmware (OVMF) file to be used in validating the measurements

    Returned as hex encoded string"""

    # https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html
    # The value of GCTX.LD is SHA256(firmware_blob || kernel_hashes_blob || vmsas_blob), where:
    #     firmware_blob is the content of the entire firmware flash file (for example, OVMF.fd). [...]
    # and verified again sevctl, see tests
    firmware_content = firmware_path.read_bytes()
    hash_calculator = hashlib.sha256(firmware_content)

    return hash_calculator.hexdigest()


def compute_confidential_measure(
    sev_info: SEVInfo, tik: bytes, expected_hash: str, nonce: bytes
) -> hmac.HMAC:
    """
    Computes the SEV measurement using the CRN SEV data and local variables like the OVMF firmware hash,
    and the session key generated.
    """

    h = hmac.new(tik, digestmod="sha256")

    ##
    # calculated per section 6.5.2
    ##
    h.update(bytes([0x04]))
    h.update(sev_info.api_major.to_bytes(1, byteorder="little"))
    h.update(sev_info.api_minor.to_bytes(1, byteorder="little"))
    h.update(sev_info.build_id.to_bytes(1, byteorder="little"))
    h.update(sev_info.policy.to_bytes(4, byteorder="little"))

    expected_hash_bytes = bytearray.fromhex(expected_hash)
    h.update(expected_hash_bytes)

    h.update(nonce)

    return h


def make_secret_table(secret: str) -> bytearray:
    """
    Makes the disk secret table to be sent to the Confidential CRN
    """

    ##
    # Construct the secret table: two guids + 4 byte lengths plus string
    # and zero terminator
    #
    # Secret layout is  guid, len (4 bytes), data
    # with len being the length from start of guid to end of data
    #
    # The table header covers the entire table then each entry covers
    # only its local data
    #
    # our current table has the header guid with total table length
    # followed by the secret guid with the zero terminated secret
    ##

    # total length of table: header plus one entry with trailing \0
    length = 16 + 4 + 16 + 4 + len(secret) + 1
    # SEV-ES requires rounding to 16
    length = (length + 15) & ~15
    secret_table = bytearray(length)

    secret_table[0:16] = UUID("{1e74f542-71dd-4d66-963e-ef4287ff173b}").bytes_le
    secret_table[16:20] = len(secret_table).to_bytes(4, byteorder="little")
    secret_table[20:36] = UUID("{736869e5-84f0-4973-92ec-06879ce3da0b}").bytes_le
    secret_table[36:40] = (16 + 4 + len(secret) + 1).to_bytes(4, byteorder="little")
    secret_table[40 : 40 + len(secret)] = secret.encode()

    return secret_table


def encrypt_secret_table(secret_table: bytes, tek: bytes, iv: bytes) -> bytes:
    """Encrypt the secret table with the TEK in CTR mode using a random IV"""

    # Initialize the cipher with AES algorithm and CTR mode
    cipher = Cipher(algorithms.AES(tek), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the secret table
    encrypted_secret = encryptor.update(secret_table) + encryptor.finalize()

    return encrypted_secret


def make_packet_header(
    vm_measure: bytes,
    encrypted_secret_table: bytes,
    secret_table_size: int,
    tik: bytes,
    iv: bytes,
) -> bytearray:
    """
    Creates a packet header using the encrypted disk secret table to be sent to the Confidential CRN
    """

    ##
    # ultimately needs to be an argument, but there's only
    # compressed and no real use case
    ##
    flags = 0

    ##
    # Table 55. LAUNCH_SECRET Packet Header Buffer
    ##
    header = bytearray(52)
    header[0:4] = flags.to_bytes(4, byteorder="little")
    header[4:20] = iv

    h = hmac.new(tik, digestmod="sha256")
    h.update(bytes([0x01]))
    # FLAGS || IV
    h.update(header[0:20])
    h.update(secret_table_size.to_bytes(4, byteorder="little"))
    h.update(secret_table_size.to_bytes(4, byteorder="little"))
    h.update(encrypted_secret_table)
    h.update(vm_measure)

    header[20:52] = h.digest()

    return header
