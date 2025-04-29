from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field  # , Schema


class DateTimeModelMixin(BaseModel):
    created_at: Optional[datetime] = None  #= Schema(..., alias="createdAt")
    updated_at: Optional[datetime] = None  #= Schema(..., alias="updatedAt")


class DBModelMixin(DateTimeModelMixin):
    id: Optional[str] = None
    #id: Optional[int] = Field(..., alias='_id')

