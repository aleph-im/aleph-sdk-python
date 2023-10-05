from datetime import datetime
from typing import Iterable, Optional, Union

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
