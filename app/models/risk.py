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


import random
from typing import Optional, List
from pydantic import BaseModel
from enum import Enum

from .dbmodel import DateTimeModelMixin, DBModelMixin
from .rwmodel import RWModel
from .snake2camel import to_camel

class RiskLevelEnum(Enum):
    VeryLow = 0
    Low = 1
    Medium = 2
    High = 3
    VeryHigh = 4

class AdditionalProperty(BaseModel):
    key: str = ""
    value: str = ""

class Asset(BaseModel):
    label: str
    type: Optional[str]
    uri: str
    identifier: Optional[str]
    additional_properties: Optional[List[AdditionalProperty]]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class Consequence(BaseModel):
    asset: Asset
    label: str
    description: str
    impact: str
    likelihood: str
    risk: str
    uri: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class RiskVector(BaseModel):
    very_high: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    very_low: int = 0

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

    def random_level(self):
        levels = ["Very High", "High", "Medium", "Low", "Very Low"]
        return levels[random.randrange(len(levels))]

    def randomise(self):
        self.high = random.randint(0, 1000)
        self.low = random.randint(0, 1000)
        self.medium = random.randint(0, 1000)
        self.very_low = random.randint(0, 1000)
        self.very_high = random.randint(0, 1000)

    def __eq__(self, other):
        return self.low == other.low and \
                self.very_low == other.very_low and \
                self.medium == other.medium and \
                self.high == other.high and \
                self.very_high == other.very_high

    def __gt__(self, other):
        if self.very_high - other.very_high > 0:
            return True
        elif self.very_high - other.very_high < 0:
            return False
        elif self.high - other.high > 0:
            return True
        elif self.high - other.high < 0:
            return False
        elif self.medium - other.medium > 0:
            return True
        elif self.medium - other.medium < 0:
            return False
        elif self.low - other.low > 0:
            return True
        elif self.low - other.low < 0:
            return False
        elif self.very_low - other.very_low > 0:
            return True
        elif self.very_low - other.very_low < 0:
            return False
        else:
            return False

    def __lt__(self, other):
        if self.very_high - other.very_high < 0:
            return True
        if self.very_high - other.very_high > 0:
            return False
        elif self.high - other.high < 0:
            return True
        elif self.high - other.high > 0:
            return False
        elif self.medium - other.medium < 0:
            return True
        elif self.medium - other.medium > 0:
            return False
        elif self.low - other.low < 0:
            return True
        elif self.low - other.low > 0:
            return False
        elif self.very_low - other.very_low < 0:
            return True
        elif self.very_low - other.very_low > 0:
            return False
        else:
            return False

    def overall_level(self):
        if self.very_high > 0:
            return 'Very High'
        elif self.high > 0:
            return 'High'
        elif self.medium > 0:
            return 'Medium'
        elif self.low > 0:
            return 'Low'
        elif self.very_low > 0:
            return 'Very Low'
        else:
            return None

class Risk(BaseModel):
    overall: str
    components: RiskVector

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class State(BaseModel):
    risk: Risk
    consequences: Optional[List[Consequence]] = None

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class StateInDB(DBModelMixin, DateTimeModelMixin, RWModel, State):
    jobid: Optional[str]

