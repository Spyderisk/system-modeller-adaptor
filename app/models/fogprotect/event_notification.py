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

class Status(BaseModel):
    status: str

class Change(BaseModel):
    change_type: str
    attribute_changed: str
    attribute_type: str
    attribute_old_value: str
    attribute_new_value: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class ObjectToIdentify(BaseModel):
    name: str
    atid: str
    type: str

class ChangesMadeToAsIsModel(BaseModel):
    object_to_identify: ObjectToIdentify
    changes: List[Change]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class Agent(BaseModel):
    name: str
    ip: str
    id: str

class Vulnerability(BaseModel):
    #common
    source: str
    reason: str
    serviceLevel: str

    #wazuh
    rule: Optional[str]
    agent: Optional[Agent]
    filename: Optional[str]

    #fybrik
    actor: Optional[str]
    method: Optional[str]
    sub: Optional[str]
    user: Optional[str]
    role: Optional[str]
    org: Optional[str]
    endpoint: Optional[str]
    attempts: Optional[str]
    windowSize: Optional[str]
    threshold: Optional[str]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class EventNotification(BaseModel):
    event_name: str
    vulnerabilities: Vulnerability
    changes_made_to_as_is_model: List[ChangesMadeToAsIsModel]
    timestamp: int
    siea_task_id: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class Reset(BaseModel):
    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

