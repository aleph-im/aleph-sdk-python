from abc import abstractmethod
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Protocol,
    TypeVar,
    Union,
)

from aleph_message.models import ItemHash
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    TypeAdapter,
    field_validator,
)

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
    CREDIT = "CREDIT"


# Scheduler
class Period(BaseModel):
    start_timestamp: datetime
    duration_seconds: float


class PlanItem(BaseModel):
    persistent_vms: List[ItemHash] = Field(default_factory=list)
    instances: List[ItemHash] = Field(default_factory=list)
    on_demand_vms: List[ItemHash] = Field(default_factory=list)
    jobs: List[str] = Field(default_factory=list)  # adjust type if needed

    @field_validator(
        "persistent_vms", "instances", "on_demand_vms", "jobs", mode="before"
    )
    @classmethod
    def coerce_to_list(cls, v: Any) -> List[Any]:
        # Treat None or empty dict as empty list
        if v is None or (isinstance(v, dict) and not v):
            return []
        return v


class SchedulerPlan(BaseModel):
    period: Period
    plan: Dict[str, PlanItem]

    model_config = {
        "populate_by_name": True,
    }


class NodeItem(BaseModel):
    node_id: str
    url: str
    ipv6: Optional[str] = None
    supports_ipv6: bool


class SchedulerNodes(BaseModel):
    nodes: List[NodeItem]

    model_config = {
        "populate_by_name": True,
    }

    def get_url(self, node_id: str) -> Optional[str]:
        """
        Return the URL for the given node_id, or None if not found.
        """
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None


class AllocationItem(BaseModel):
    vm_hash: ItemHash
    vm_type: str
    vm_ipv6: Optional[str] = None
    period: Period
    node: NodeItem

    model_config = {
        "populate_by_name": True,
    }


class InstanceWithScheduler(BaseModel):
    source: Literal["scheduler"]
    allocations: Optional[
        AllocationItem
    ]  # Case Scheduler (None == allocation can't be find on scheduler)


class InstanceManual(BaseModel):
    source: Literal["manual"]
    crn_url: str  # Case


class InstanceAllocationsInfo(
    RootModel[Dict[ItemHash, Union[InstanceManual, InstanceWithScheduler]]]
):
    """
    RootModel holding mapping ItemHash to its Allocations.
    Uses item_hash as the key instead of InstanceMessage objects to avoid hashability issues.
    """

    pass


# CRN Executions


class Networking(BaseModel):
    ipv4: str
    ipv6: str


class CrnExecutionV1(BaseModel):
    networking: Networking


class PortMapping(BaseModel):
    host: int
    tcp: bool
    udp: bool


class NetworkingV2(BaseModel):
    ipv4_network: str
    host_ipv4: str
    ipv6_network: str
    ipv6_ip: str
    mapped_ports: Dict[str, PortMapping]


class VmStatus(BaseModel):
    defined_at: Optional[datetime]
    preparing_at: Optional[datetime]
    prepared_at: Optional[datetime]
    starting_at: Optional[datetime]
    started_at: Optional[datetime]
    stopping_at: Optional[datetime]
    stopped_at: Optional[datetime]


class CrnExecutionV2(BaseModel):
    networking: NetworkingV2
    status: VmStatus
    running: bool


class CrnV1List(RootModel[Dict[ItemHash, CrnExecutionV1]]):
    """
    V1: a dict whose keys are ItemHash (strings)
    and whose values are VmItemV1 (just `networking`).
    """

    pass


class CrnV2List(RootModel[Dict[ItemHash, CrnExecutionV2]]):
    """
    A RootModel whose root is a dict mapping each item‐hash (string)
    to a CrnExecutionV2, exactly matching your JSON structure.
    """

    pass


class InstancesExecutionList(
    RootModel[Dict[ItemHash, Union[CrnExecutionV1, CrnExecutionV2]]]
):
    """
    A Root Model representing Instances Message hashes and their Executions.
    Uses ItemHash as keys to avoid hashability issues with InstanceMessage objects.
    """

    pass


class IPV4(BaseModel):
    public: str
    local: str


class Dns(BaseModel):
    name: str
    item_hash: ItemHash
    ipv4: Optional[IPV4]
    ipv6: str


DnsListAdapter = TypeAdapter(list[Dns])


class PortFlags(BaseModel):
    tcp: bool
    udp: bool


class Ports(BaseModel):
    ports: Dict[int, PortFlags]


AllForwarders = RootModel[Dict[ItemHash, Optional[Ports]]]


class DictLikeModel(BaseModel):
    """
    Base class: behaves like a dict while still being a Pydantic model.
    """

    # allow extra fields + validate on assignment
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def __iter__(self) -> Iterator[str]:
        return iter(self.model_dump().keys())

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def keys(self):
        return self.model_dump().keys()

    def values(self):
        return self.model_dump().values()

    def items(self):
        return self.model_dump().items()

    def get(self, key: str, default=None):
        return getattr(self, key, default)


class VoucherAttribute(BaseModel):
    value: Union[str, Decimal]
    trait_type: str = Field(..., alias="trait_type")
    display_type: Optional[str] = Field(None, alias="display_type")


class VoucherMetadata(BaseModel):
    name: str
    description: str
    external_url: str
    image: str
    icon: str
    attributes: list[VoucherAttribute]


class Voucher(BaseModel):
    id: str
    metadata_id: str
    name: str
    description: str
    external_url: str
    image: str
    icon: str
    attributes: list[VoucherAttribute]
