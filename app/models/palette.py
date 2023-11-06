
from typing import Optional, List, Dict
from pydantic import BaseModel

from .snake2camel import to_camel

def to_camel_cx(string: str) -> str:
    #return ''.join(word.capitalize() for word in string.split('_'))
    if string in ["obj_id", "obj_type"]:
        return string.split('_')[1]
    else:
        sp = string.split('_')
        return sp[0] + ''.join(word.capitalize() for word in sp[1:])

def to_camel_c(string: str) -> str:
    #return ''.join(word.capitalize() for word in string.split('_'))
    sp = string.split('_')
    return sp[0] + ''.join(word.capitalize() for word in sp[1:])

class BaseAsset(BaseModel):
    pass

class Asset(BaseModel):
    id: str
    label: str
    category: str
    assertable: bool
    type: List[str]
    icon: str
    description: str
    min_cardinality: int
    max_cardinality: int

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class LinkElement(BaseModel):
    type: str
    label: str
    comment: str
    inferred: bool
    options: List[str]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class Link(BaseModel):
    links_from: Optional[List[LinkElement]]
    links_to: Optional[List[LinkElement]]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class Palette(BaseModel):
    assets: List[Asset]
    links: Dict[str, Link]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

