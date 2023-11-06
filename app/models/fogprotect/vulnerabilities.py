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


def to_camel(string: str) -> str:
    return ''.join(word.capitalize() for word in string.split('_'))

class ObjectToIdentify(BaseModel):
    object_name: str
    object_type: Optional[str]
    object_i_d: Optional[str]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class Vulnerability(BaseModel):
    object_to_identify: ObjectToIdentify
    event_status: str
    event_name: str
    timestamp: int
    offset: int
    partition: int
    c_v_s_s: str

class Vulnerabilities(BaseModel):
    vulnerabilities: List[Vulnerability]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

