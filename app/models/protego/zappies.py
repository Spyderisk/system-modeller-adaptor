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
##      Created Date :          2021-05-11
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////


from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class Method(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class Instance(BaseModel):
    uri: str
    method: Method
    param: Optional[str]
    evidence: Optional[str]
    attack: Optional[str]


class Alert(BaseModel):
    pluginid: int
    alert_ref: Optional[int]
    alert: str
    name: str
    riskcode: int
    confidence: int
    riskdesc: str
    desc: str
    instances: List[Instance]
    count: int
    solution: str
    otherinfo: Optional[str]
    reference: str
    cweid: Optional[str]
    wascid: Optional[str]
    sourceid: int


class Site(BaseModel):
    name: str = Field(None, alias='@name')
    host: str = Field(None, alias='@host')
    port: str = Field(None, alias='@port')
    ssl: bool = Field(None, alias='@ssl')
    alerts: List[Alert]


class Zappies(BaseModel):
    version: str = Field(None, alias='@version')
    generated: str = Field(None, alias='@generated')
    site: List[Site]
