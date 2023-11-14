from typing import Optional, Mapping, List, Any

from aleph_message.models.execution.base import Encoding
from aleph_message.models.execution.environment import FunctionEnvironment, MachineResources

from aleph.sdk.types import StorageEnum


class VmParams:
    """
    Parameters for creating a VM.
    """
    environment_variables: Optional[Mapping[str, str]]
    storage_engine: StorageEnum
    channel: Optional[str]
    address: Optional[str]
    memory: Optional[int]
    vcpus: Optional[int]
    timeout_seconds: Optional[float]
    persistent: bool
    allow_amend: bool
    internet: bool
    aleph_api: bool
    encoding: Encoding
    volumes: Optional[List[Mapping]]
    subscriptions: Optional[List[Mapping]]
    metadata: Optional[Mapping[str, Any]]

    def __init__(
        self,
        environment_variables: Optional[Mapping[str, str]] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        memory: Optional[int] = None,
        vcpus: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        persistent: bool = False,
        allow_amend: bool = False,
        internet: bool = True,
        aleph_api: bool = True,
        encoding: Encoding = Encoding.zip,
        volumes: Optional[List[Mapping]] = None,
        subscriptions: Optional[List[Mapping]] = None,
        metadata: Optional[Mapping[str, Any]] = None
    ):
        self.environment_variables = environment_variables
        self.storage_engine = storage_engine
        self.channel = channel
        self.address = address
        self.memory = memory
        self.vcpus = vcpus
        self.timeout_seconds = timeout_seconds
        self.persistent = persistent
        self.allow_amend = allow_amend
        self.internet = internet
        self.aleph_api = aleph_api
        self.encoding = encoding
        self.volumes = volumes
        self.subscriptions = subscriptions
        self.metadata = metadata

    @property
    def function_environment(self) -> FunctionEnvironment:
        return FunctionEnvironment(
            reproducible=False,
            internet=self.internet,
            aleph_api=self.aleph_api,
        )

    @property
    def machine_resources(self) -> MachineResources:
        return MachineResources(
            vcpus=self.vcpus,
            memory=self.memory,
            seconds=self.timeout_seconds,
        )
