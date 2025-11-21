from typing import Dict, List, Optional
from pydantic import BaseModel, Field, RootModel

from ..dbmodel import DateTimeModelMixin, DBModelMixin
from ..rwmodel import RWModel
from ..snake2camel import to_camel

from datetime import datetime, timedelta
from dateutil import parser


class ProductMapDict(RootModel[Dict[str, List[str]]]):
    """Map of asset names to list of products."""
    pass


class ProductMap(BaseModel):
    data: Dict[str, List[str]] = Field(default_factory=dict)
    webkey: Optional[str] = None


class ProductMapInDB(DBModelMixin, DateTimeModelMixin, RWModel, ProductMap):
    ssm_model_id: Optional[str] = None

