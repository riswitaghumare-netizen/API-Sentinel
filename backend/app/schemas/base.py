from typing import Generic, TypeVar, Optional, Any, List
from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class PaginationMeta(BaseModel):
    total: int
    page: int = 1
    page_size: int = 50
    total_pages: int = 1


class ApiErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class ApiResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(from_attributes=True)
    
    success: bool = True
    data: Optional[T] = None
    meta: Optional[dict] = None


class ApiErrorResponse(BaseModel):
    success: bool = False
    error: ApiErrorDetail
