from abc import abstractmethod
from decimal import Decimal
from enum import Enum
from typing import Dict, Optional, Protocol, TypeVar, Union

from pydantic import BaseModel, Field

__all__ = ("StorageEnum", "Account", "AccountFromPrivateKey", "GenericMessage")

from aleph_message.models import AlephMessage, Chain


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

    def __init__(self, private_key: bytes, chain: Chain): ...

    async def sign_raw(self, buffer: bytes) -> bytes: ...

    def export_private_key(self) -> str: ...

    def switch_chain(self, chain: Optional[str] = None) -> None: ...


GenericMessage = TypeVar("GenericMessage", bound=AlephMessage)


class SEVInfo(BaseModel):
    """
    An AMD SEV platform information.
    """

    enabled: bool
    api_major: int
    api_minor: int
    build_id: int
    policy: int
    state: str
    handle: int


class SEVMeasurement(BaseModel):
    """
    A SEV measurement data get from Qemu measurement.
    """

    sev_info: SEVInfo
    launch_measure: str


class ChainInfo(BaseModel):
    """
    A chain information.
    """

    chain_id: int
    rpc: str
    token: Optional[str] = None
    super_token: Optional[str] = None
    active: bool = True


class StoredContent(BaseModel):
    """
    A stored content.
    """

    filename: Optional[str] = Field(default=None)
    hash: Optional[str] = Field(default=None)
    url: Optional[str] = Field(default=None)
    error: Optional[str] = Field(default=None)


class TokenType(str, Enum):
    """
    A token type.
    """

    GAS = "GAS"
    ALEPH = "ALEPH"


class VoucherAttribute(BaseModel):
    value: Union[str, Decimal]
    trait_type: str = Field(..., alias="trait_type")
    display_type: Optional[str] = Field(None, alias="display_type")


class VoucherMetadata(BaseModel):
    name: str
    description: str
    external_url: str = Field(..., alias="external_url")
    image: str
    icon: str
    attributes: list[VoucherAttribute]


class Voucher(BaseModel):
    id: str
    metadata_id: str = Field(..., alias="metadata_id")
    name: str
    description: str
    external_url: str = Field(..., alias="external_url")
    image: str
    icon: str
    attributes: list[VoucherAttribute]
