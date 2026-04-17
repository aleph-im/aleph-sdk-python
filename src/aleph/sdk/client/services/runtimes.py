import logging
from enum import Enum
from typing import TYPE_CHECKING, List, Optional

from pydantic import BaseModel

from aleph.sdk.conf import settings

if TYPE_CHECKING:
    from aleph.sdk.client.http import AlephHttpClient

logger = logging.getLogger(__name__)


class RuntimeType(str, Enum):
    PROGRAM = "program"
    INSTANCE = "instance"
    RESCUE = "rescue"
    FIRMWARE = "firmware"


class RuntimeEntry(BaseModel):
    """A single runtime entry from the runtimes aggregate."""

    id: str
    name: str
    type: RuntimeType
    item_hash: str
    default: bool = False
    sha256: Optional[str] = None
    firmware_hash: Optional[str] = None


class RuntimesAggregate(BaseModel):
    """The runtimes aggregate payload."""

    entries: List[RuntimeEntry] = []


class Runtimes:
    """Service to fetch and query the runtimes aggregate."""

    def __init__(self, client: "AlephHttpClient"):
        self._client = client

    async def get_runtimes_aggregate(self) -> RuntimesAggregate:
        """Fetch the full runtimes aggregate."""
        aggregate_data = await self._client.fetch_aggregate(
            address=settings.ALEPH_AGGREGATE_ADDRESS,
            key="runtimes",
        )
        if not aggregate_data:
            logger.warning("Runtimes aggregate is empty or not found")
            return RuntimesAggregate()
        return RuntimesAggregate.model_validate(aggregate_data)

    async def get_runtimes(
        self, runtime_type: Optional[RuntimeType] = None
    ) -> List[RuntimeEntry]:
        """Get runtime entries, optionally filtered by type.

        Args:
            runtime_type: Filter by RuntimeType. If None, returns all entries.
        """
        aggregate = await self.get_runtimes_aggregate()
        if runtime_type is None:
            return aggregate.entries
        return [r for r in aggregate.entries if r.type == runtime_type]

    async def get_default_runtime(
        self, runtime_type: RuntimeType
    ) -> Optional[RuntimeEntry]:
        """Get the default entry for a given type.

        Args:
            runtime_type: The type to look up (e.g. "rescue", "instance").

        Returns:
            The default RuntimeEntry, or None if no default is set.
        """
        entries = await self.get_runtimes(runtime_type)
        for entry in entries:
            if entry.default:
                return entry
        return None
