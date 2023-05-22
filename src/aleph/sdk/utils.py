import errno
import logging
import os
from enum import Enum
from pathlib import Path
from shutil import make_archive
from typing import Tuple, Type, Union
from zipfile import BadZipFile, ZipFile

from aleph_message.models import MessageType
from aleph_message.models.execution.program import Encoding

from aleph.sdk.conf import settings
from aleph.sdk.types import GenericMessage

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


def enum_as_str(obj: Union[str, Enum]) -> str:
    """Returns the value of an Enum, or the string itself when passing a string.

    Python 3.11 adds a new formatting of string enums.
    `str(MyEnum.value)` becomes `MyEnum.value` instead of `value`.
    """
    if not isinstance(obj, str):
        raise TypeError(f"Unsupported enum type: {type(obj)}")

    if isinstance(obj, Enum):
        return obj.value

    return obj
