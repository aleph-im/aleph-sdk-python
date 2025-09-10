import asyncio
from typing import TYPE_CHECKING, Any, List, Optional, Tuple, Union

from aleph_message.models import InstanceMessage, ItemHash, MessageType, PaymentType
from aleph_message.status import MessageStatus

from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.query.responses import MessagesResponse

if TYPE_CHECKING:
    from aleph.sdk.client.http import AlephHttpClient

from aleph.sdk.types import (
    CrnExecutionV1,
    CrnExecutionV2,
    InstanceAllocationsInfo,
    InstanceManual,
    InstancesExecutionList,
    InstanceWithScheduler,
)
from aleph.sdk.utils import safe_getattr, sanitize_url


class Instance:
    """
    This is utils functions that used multiple Service
    exemple getting info about Allocations / exeuction of any instances (hold or not)
    """

    def __init__(self, client: "AlephHttpClient"):
        self._client = client

    async def get_name_of_executable(self, item_hash: ItemHash) -> Optional[str]:
        try:
            message: Any = await self._client.get_message(item_hash=item_hash)
            if hasattr(message, "content") and hasattr(message.content, "metadata"):
                return message.content.metadata.get("name")
            elif isinstance(message, dict):
                # Handle dictionary response format
                if "content" in message and isinstance(message["content"], dict):
                    if "metadata" in message["content"] and isinstance(
                        message["content"]["metadata"], dict
                    ):
                        return message["content"]["metadata"].get("name")
            return None
        except Exception:
            return None

    async def get_instance_allocation_info(
        self, msg: InstanceMessage, crn_list: dict
    ) -> Tuple[InstanceMessage, Union[InstanceManual, InstanceWithScheduler]]:
        vm_hash = msg.item_hash
        payment_type = safe_getattr(msg, "content.payment.type.value")
        firmware = safe_getattr(msg, "content.environment.trusted_execution.firmware")
        has_gpu = safe_getattr(msg, "content.requirements.gpu")

        is_hold = payment_type == PaymentType.hold.value
        is_conf = bool(firmware and len(firmware) == 64)

        if is_hold and not is_conf and not has_gpu:
            alloc = await self._client.scheduler.get_allocation(vm_hash)
            info = InstanceWithScheduler(source="scheduler", allocations=alloc)
        else:
            crn_hash = safe_getattr(msg, "content.requirements.node.node_hash")
            if isinstance(crn_list, list):
                node = next((n for n in crn_list if n.get("hash") == crn_hash), None)
                url = sanitize_url(node.get("address")) if node else ""
            else:
                node = crn_list.get(crn_hash)
                url = sanitize_url(node.get("address")) if node else ""

            info = InstanceManual(source="manual", crn_url=url)
        return msg, info

    async def get_instances(self, address: str) -> List[InstanceMessage]:
        resp: MessagesResponse = await self._client.get_messages(
            message_filter=MessageFilter(
                message_types=[MessageType.instance],
                addresses=[address],
                message_statuses=[MessageStatus.PROCESSED, MessageStatus.REMOVING],
            ),
            page_size=100,
        )
        return resp.messages

    async def get_instances_allocations(self, messages_list, only_processed=True):
        crn_list_response = await self._client.crn.get_crns_list()
        crn_list = crn_list_response.get("crns", {})

        tasks = []
        for msg in messages_list:
            if only_processed:
                status = await self._client.get_message_status(msg.item_hash)
                if (
                    status != MessageStatus.PROCESSED
                    and status != MessageStatus.REMOVING
                ):
                    continue
            tasks.append(self.get_instance_allocation_info(msg, crn_list))

        results = await asyncio.gather(*tasks)

        mapping = {ItemHash(msg.item_hash): info for msg, info in results}

        return InstanceAllocationsInfo.model_validate(mapping)

    async def get_instance_executions_info(
        self, instances: InstanceAllocationsInfo
    ) -> InstancesExecutionList:
        async def _fetch(
            item_hash: ItemHash,
            alloc: Union[InstanceManual, InstanceWithScheduler],
        ) -> tuple[str, Optional[Union[CrnExecutionV1, CrnExecutionV2]]]:
            """Retrieve the execution record for an item hash."""
            if isinstance(alloc, InstanceManual):
                crn_url = sanitize_url(alloc.crn_url)
            else:
                if not alloc.allocations:
                    return str(item_hash), None
                crn_url = sanitize_url(alloc.allocations.node.url)

            if not crn_url:
                return str(item_hash), None

            try:
                execution = await self._client.crn.get_vm(
                    item_hash=item_hash,
                    crn_address=crn_url,
                )
                return str(item_hash), execution
            except Exception:
                return str(item_hash), None

        fetch_tasks = []
        msg_hash_map = {}

        for item_hash, alloc in instances.root.items():
            fetch_tasks.append(_fetch(item_hash, alloc))
            msg_hash_map[str(item_hash)] = item_hash

        results = await asyncio.gather(*fetch_tasks)

        mapping = {
            ItemHash(msg_hash): exec_info
            for msg_hash, exec_info in results
            if msg_hash is not None and exec_info is not None
        }

        return InstancesExecutionList.model_validate(mapping)
