##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2021
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre of Gamma House, Enterprise Road,
## Chilworth Science Park, Southampton, SO16 7NS, UK.
##
## This software may not be used, sold, licensed, transferred, copied
## or reproduced in whole or in part in any manner or form or in or
## on any media by any person other than in accordance with the terms
## of the Licence Agreement supplied with the software, or otherwise
## without the prior written consent of the copyright owners.
##
## This software is distributed WITHOUT ANY WARRANTY, without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
## PURPOSE, except where stated in the Licence Agreement supplied with
## the software.
##
##      Created By :            Panos Melas
##      Created Date :          2021-04-29
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////


from typing import List
from pydantic import BaseModel

from .snake2camel import to_camel

def to_camel1(string: str) -> str:
    return ''.join(word.capitalize() for word in string.split('_'))

class AdditionalProperty(BaseModel):
    key: str
    value: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AssetMetadata(BaseModel):
    asset_id: str
    asset_label: str
    additional_properties: List[AdditionalProperty]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AssetMetadataList(BaseModel):
    asset_list: List[AssetMetadata]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


