from abc import abstractmethod
from enum import Enum
from typing import Dict, Protocol, TypeVar

from pydantic import BaseModel

__all__ = ("StorageEnum", "Account", "AccountFromPrivateKey", "GenericMessage")

from aleph_message.models import AlephMessage


class StorageEnum(str, Enum):
    ipfs = "ipfs"
    storage = "storage"


# Use a protocol to avoid importing crypto libraries
class Account(Protocol):
    CHAIN: str
    CURVE: str

    @abstractmethod
    async def sign_message(self, message: Dict) -> Dict: ...

    @abstractmethod
    async def sign_raw(self, buffer: bytes) -> bytes: ...

    @abstractmethod
    def get_address(self) -> str: ...

    @abstractmethod
    def get_public_key(self) -> str: ...


class AccountFromPrivateKey(Account, Protocol):
    """Only accounts that are initialized from a private key string are supported."""

    def __init__(self, private_key: bytes): ...

    async def sign_raw(self, buffer: bytes) -> bytes: ...


GenericMessage = TypeVar("GenericMessage", bound=AlephMessage)


class SEVInfo(BaseModel):
    """
    An AMD SEV platform information.
    """

    enabled: bool


class SEVMeasurement(BaseModel):
    """
    A SEV measurement data get from Qemu measurement.
    """

    sev_info: SEVInfo
    launch_measure: str
