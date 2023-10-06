from pydantic import BaseModel


class PaginationResponse(BaseModel):
    pagination_page: int
    pagination_total: int
    pagination_per_page: int
    pagination_item: str
