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
##      Created By :            Ken Meacham
##      Created Date :          2021-04-29
##      Created for Project :   FogProtect
##
##///////////////////////////////////////////////////////////////////////


from typing import Optional, List
from pydantic import BaseModel

from app.models.risk import RiskVector

def to_camel(string: str) -> str:
    return ''.join(word.capitalize() for word in string.split('_'))

class RiskLevel(BasicModel):
    overall_risk_level: str
    risk_vector: RiskVector

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class AsIsRisk(BasicModel):
    id: str
    risk_level: RiskLevel

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class Change(BasicModel):
    action: str
    change_type: str
    attribute_changed: str
    attribute_type: str
    attribute_old_value: str
    attribute_new_value: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class ObjectToIdentify(BasicModel):
    object_name: str
    object_type: str
    object_id: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class ObjectChange(BasicModel):
    object_to_identify: ObjectToIdentify
    changes: List[Change]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class Recommendation(BasicModel):
    object_changes: List[ObjectChange]
    risk_level: RiskLevel

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class AsIsRiskResponse(BasicModel):
    as_is_risk: AsIsRisk
    acceptable_risk_level: str
    recommendations: List[Recommendation]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

