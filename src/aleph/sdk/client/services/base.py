from abc import ABC
from typing import TYPE_CHECKING, Generic, List, Optional, Type, TypeVar

from pydantic import BaseModel

if TYPE_CHECKING:
    from aleph.sdk.client.http import AlephHttpClient


T = TypeVar("T", bound=BaseModel)


class AggregateConfig(BaseModel, Generic[T]):
    """
    A generic container for "aggregate" data of type T.
    - `data` will be either None or a list of T-instances.
    """

    data: Optional[List[T]] = None


class BaseService(ABC, Generic[T]):
    aggregate_key: str
    model_cls: Type[T]

    def __init__(self, client: "AlephHttpClient"):
        self._client = client
        self.model_cls: Type[T]

    async def get_config(self, address: str):

        aggregate_data = await self._client.fetch_aggregate(
            address=address, key=self.aggregate_key
        )

        if aggregate_data:
            model_instance = self.model_cls.model_validate(aggregate_data)
            config = AggregateConfig[T](data=[model_instance])
        else:
            config = AggregateConfig[T](data=None)

        return config
