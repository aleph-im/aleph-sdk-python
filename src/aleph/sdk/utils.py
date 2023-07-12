import errno
import logging
import os
from pathlib import Path
from shutil import make_archive
from typing import Tuple, Type
from zipfile import BadZipFile, ZipFile

from aleph_message.models import MessageType
from aleph_message.models.program import Encoding

from aleph.sdk.conf import settings
from aleph.sdk.types import GenericMessage

from typing import (
    Tuple,
    Type,
    TypeVar,
    Protocol,
)

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


C = TypeVar("C", str, bytes, covariant=True)
U = TypeVar("U", str, bytes, contravariant=True)


class AsyncReadable(Protocol[C]):
    async def read(self, n: int = -1) -> C:
        ...


class Writable(Protocol[U]):
    def write(self, buffer: U) -> int:
        ...


async def copy_async_readable_to_buffer(
    readable: AsyncReadable[C], buffer: Writable[C], chunk_size: int
):
    while True:
        chunk = await readable.read(chunk_size)
        if not chunk:
            break
        buffer.write(chunk)
