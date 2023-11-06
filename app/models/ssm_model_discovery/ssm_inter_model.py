from typing import Optional, List, Dict
from pydantic import BaseModel

#from ..snake2camel import to_camel

def to_camel(string: str) -> str:
    #return ''.join(word.capitalize() for word in string.split('_'))
    sp = string.split('_')
    return sp[1] + ''.join(word.capitalize() for word in sp[2:])


class ImAsset(BaseModel):
    ima_label: str
    ima_type: str
    ima_asserted: bool
    ima_visible: bool
    ima_icon_x: int
    ima_icon_y: int
    ima_min_cardinality: int
    ima_max_cardinality: int

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class ImLink(BaseModel):
    iml_from: str
    iml_fromID: str
    iml_to: str
    iml_toID: str
    iml_label: str
    iml_type: str
    iml_asserted: bool
    iml_visible: bool

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class SSMIntermediateModel(BaseModel):
    imm_desc: str = ""
    imm_name: str = ""
    imm_location: str = ""
    imm_assets: List[ImAsset] = []
    imm_links: List[ImLink] = []

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True



