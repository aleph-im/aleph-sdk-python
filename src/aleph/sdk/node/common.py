import json
from functools import partial
from typing import Generic, Optional, TypeVar

from peewee import SqliteDatabase
from playhouse.sqlite_ext import JSONField
from pydantic import BaseModel

from aleph.sdk.conf import settings

db = SqliteDatabase(settings.CACHE_DATABASE_PATH)
T = TypeVar("T", bound=BaseModel)


class JSONDictEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BaseModel):
            return obj.dict()
        return json.JSONEncoder.default(self, obj)


pydantic_json_dumps = partial(json.dumps, cls=JSONDictEncoder)


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
        return value.json()

    def python_value(self, value: Optional[str]) -> Optional[T]:
        if value is None:
            return None
        return self.type.parse_raw(value)
