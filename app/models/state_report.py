##///////////////////////////////////////////////////////////////////////
##
## © University of Southampton IT Innovation Centre, 2023
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre, Highfield Campus, SO17 1BJ, UK.
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
##      Created Date :          2023-09-12
##      Created for Project :   Cyberkit4SME
##
##///////////////////////////////////////////////////////////////////////


import random
from typing import Optional, List, Union
from typing import ForwardRef
from pydantic import BaseModel, Field, validator, root_validator
from enum import Enum

from .dbmodel import DateTimeModelMixin, DBModelMixin
from .rwmodel import RWModel
from .snake2camel import to_camel

from datetime import datetime, timedelta
from dateutil import parser

from fastapi.logger import logger


class AdditionalProperty(BaseModel):
    key: str = ""
    value: str = ""

AssetDesc = ForwardRef('AssetDesc')


class Relation(BaseModel):
    type: str
    to: Optional[AssetDesc]


class AssetDesc(BaseModel):
    id: Optional[str]
    label: Optional[str]
    type: Optional[str]
    uri: Optional[str]
    properties: Optional[List[AdditionalProperty]]
    relation: Optional[List[Relation]]

Relation.update_forward_refs()

class TypeEnum(Enum):
    everything = "everything"
    exceptions = "exceptions"

class ExpiryTypeEnum(Enum):
    newest = "newest"
    period = "period"
    timestamp = "timestamp"

class Expiry(BaseModel):
    type: ExpiryTypeEnum
    time: Union[int, str, None] = Field(None, description="Number of seconds (for period) or ISO date-time string (for timestamp)")
    label: Optional[str] = Field(None, description="A label (required if type is newest)")

    @validator("label", pre=True, always=True)
    def validate_label(cls, value, values, **kwargs):
        ttype = values.get("type")
        if ttype == "newest" and not value:
            raise ValueError("label must be provided when type is newest")
        return value


    class Config:
        use_enum_values = True

    def parse(self, date=None):
        if ExpiryTypeEnum(self.type) is ExpiryTypeEnum.newest:
            return True
        elif ExpiryTypeEnum(self.type) is ExpiryTypeEnum.period:
            expire_ts = date + timedelta(seconds=self.time)
            return expire_ts > datetime.now()
        elif ExpiryTypeEnum(self.type) is ExpiryTypeEnum.timestamp:
            expire_ts = parser.parse(self.time).timestamp()
            return expire_ts > datetime.now().timestamp()
        else:
            return False

class ScopeTypeEnum(Enum):
    all = "all"
    embedded = "embedded"
    resource = "resource"

class Scope(BaseModel):
    type: ScopeTypeEnum
    uri: Optional[str]
    label: Optional[str]
    items: Optional[dict]

    class Config:
        use_enum_values = True


class OperatorEnum(Enum):
    EQ = "="
    GE = ">="
    LE = "<="

#TODO update levels dynamically
twa_levels = {
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelVeryLow": 0,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelLow": 1,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelMedium": 2,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelHigh": 3,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelVeryHigh": 4,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelSafe": 5
}

class Trustworthiness(BaseModel):
    trustworthinessAttributeSet: Optional[str]
    trustworthinessAttribute: Optional[str]
    level: str
    operator: OperatorEnum

    @root_validator()
    def validate_twas_and_attribute(cls, values):
        twas = values.get("trustworthinessAttributeSet")
        twa = values.get("trustworthinessAttribute")
        if not twas and not twa:
            raise ValueError("neither trustworthinessAttributeSet nor trustworthinessAttribute defined in Trustworthiness object")
        return values

    @validator("level")
    def validate_level(cls, value):
        if value not in twa_levels:
            raise ValueError("Invalid trustworthiness level")
        return value

    def __str__(self):
        if self.trustworthinessAttributeSet is not None:
            return f"trustworthinessAttributeSet: {self.trustworthinessAttributeSet[67:]}, level: {self.level[87:]}, operator: {self.operator}"
        else:
            return f"trustworthinessAttribute: {self.trustworthinessAttribute[67:]}, level: {self.level[87:]}, operator: {self.operator}"

    def __eq__(self, other):
        return self.trustworthinessAttributeSet == other.trustworthinessAttributeSet and \
                self.level == other.level and \
                self.operator == other.operator

    def __gt__(self, other):
        if self.trustworthinessAttributeSet == other.trustworthinessAttributeSet:
            return twa_levels[self.level] > twa_levels[other.level]
        return False

    def __lt__(self, other):
        if self.trustworthinessAttributeSet == other.trustworthinessAttributeSet:
            return twa_levels[self.level] < twa_levels[other.level]
        return False

    class Config:
        use_enum_values = True


impact_levels = {
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#ImpactLevelNegligible": 0,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#ImpactLevelVeryLow": 1,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#ImpactLevelLow": 2,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#ImpactLevelMedium": 3,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#ImpactLevelHigh": 4,
    "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#ImpactLevelVery": 5
}

class Impact(BaseModel):
    misbehaviourSet: Optional[str]
    misbehaviour: Optional[str]
    level: str
    operator: OperatorEnum

    @root_validator()
    def validate_impact(cls, values):
        ms = values.get("misbehaviourSet")
        m = values.get("misbehaviour")
        if not ms and not m:
            raise ValueError("neither misbehaviourSet nor misbehaviour defined in Impact object")
        return values

    @validator("level")
    def validate_level(cls, value):
        if value not in impact_levels:
            raise ValueError("Invalid impact level")
        return value

    def __eq__(self, other):
        return self.misbehaviourSet == other.misbehaviourSet and \
                self.level == other.level and \
                self.operator == other.operator

    def __gt__(self, other):
        if self.misbehaviourSet == other.misbehaviourSet:
            return impact_levels[self.level] > impact_levels[other.level]
        return False

    def __lt__(self, other):
        if self.misbehaviourSet == other.misbehaviourSet:
            return impact_levels[self.level] < impact_levels[other.level]
        return False

    class Config:
        use_enum_values = True

class Control(BaseModel):
    controlSet: Optional[str]
    control: Optional[str]
    enabled: bool

    @root_validator()
    def validate_control(cls, values):
        controlSet = values.get("controlSet")
        control = values.get("control")
        if not controlSet and not control:
            raise ValueError("neither controlSet nor control defined in Control object")
        return values

class StateItem(BaseModel):
    asset: Optional[AssetDesc]
    trustworthiness: List[Trustworthiness]
    impacts: List[Impact]
    controls: List[Control]

class StateReportMessage(BaseModel):
    state: List[StateItem]
    type: Optional[TypeEnum]
    expiry: Union[List[Expiry], None] = Field(None, description="List of expiry data. If None, the state change is intended to be permanent.")
    scope: Optional[Scope]

    def parse_expiry(self, date=None):
        return any(obj.parse(date) for obj in self.expiry)

    #class Config:
    #    json_encoders = {TypeEnum: lambda te: te.name}
    class Config:
        use_enum_values = True


class StateReportMessageInDB(DBModelMixin, DateTimeModelMixin, RWModel, StateReportMessage):
    model_id: Optional[str]


class StateReportInfo(DBModelMixin, DateTimeModelMixin, RWModel):
    model_id: Optional[str]

