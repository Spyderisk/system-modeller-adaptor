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


from typing import Optional, List
from pydantic import BaseModel
from app.models.risk import RiskVector, Risk
from app.models.risk import Asset, State

from ..dbmodel import DateTimeModelMixin, DBModelMixin
from ..rwmodel import RWModel
from ..snake2camel import to_camel

class Control(BaseModel):
    label: str
    description: Optional[str]
    uri: str
    asset: Asset
    action: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

#class Action(BaseModel):
#    control: str
#    asset: Asset
#    change: str
#
#    class Config:
#        alias_generator = to_camel
#        allow_population_by_field_name = True

class ControlStrategy(BaseModel):
    uri: str
    description: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class Recommendation(BaseModel):
    identifier: int
    category: Optional[str]
    control_strategies: List[ControlStrategy]
    controls: List[Control]
    state: State

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class CurrentState(BaseModel):
    state: State

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class ObjectRecommendation(BaseModel):
    current: CurrentState
    recommendations: Optional[List[Recommendation]]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class StoredRecInDB(DBModelMixin, DateTimeModelMixin, RWModel, ObjectRecommendation):
    jobid: Optional[str]

