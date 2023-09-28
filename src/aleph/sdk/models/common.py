from datetime import datetime
from typing import Iterable, Optional, Type, Union

from peewee import Model
from pydantic import BaseModel


class PaginationResponse(BaseModel):
    pagination_page: int
    pagination_total: int
    pagination_per_page: int
    pagination_item: str


def serialize_list(values: Optional[Iterable[str]]) -> Optional[str]:
    if values:
        return ",".join(values)
    else:
        return None


def _date_field_to_float(date: Optional[Union[datetime, float]]) -> Optional[float]:
    if date is None:
        return None
    elif isinstance(date, float):
        return date
    elif hasattr(date, "timestamp"):
        return date.timestamp()
    else:
        raise TypeError(f"Invalid type: `{type(date)}`")


def query_db_field(db_model: Type[Model], field_name: str, field_values: Iterable[str]):
    field = getattr(db_model, field_name)
    values = list(field_values)

    if len(values) == 1:
        return field == values[0]
    return field.in_(values)
