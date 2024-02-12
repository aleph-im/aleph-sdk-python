import json
from functools import partial
from typing import Generic, Optional, TypeVar

from playhouse.sqlite_ext import JSONField
from pydantic import BaseModel
from pydantic.json import pydantic_encoder

T = TypeVar("T", bound=BaseModel)


pydantic_json_dumps = partial(json.dumps, default=pydantic_encoder)


class PydanticField(JSONField, Generic[T]):
    """
    A field for storing pydantic model types as JSON in a database. Uses json for serialization.
    """

    type: T

    def __init__(self, *args, **kwargs):
        self.type = kwargs.pop("type")
        super().__init__(*args, **kwargs)

    def db_value(self, value: Optional[T]) -> Optional[str]:
        if value is None:
            return None
        return pydantic_json_dumps(value)

    def python_value(self, value: Optional[str]) -> Optional[T]:
        if not value:
            return None
        return self.type.parse_raw(value)
