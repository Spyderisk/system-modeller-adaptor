##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2023
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
##      Created Date :          2023-01-16
##      Created for Project :   Cyberkit4SME
##
##///////////////////////////////////////////////////////////////////////


from typing import Optional, List, Dict
from pydantic import BaseModel

class SSMMetadataPair(BaseModel):
    key: str
    value: str

class SSMAsset(BaseModel):
    """ data obtained by get_assets call """
    id: str
    type: str
    uri: str
    asserted: bool
    #misbehaviour_sets: Optional[Dict[str, str]]
    label: str = ""
    metadata: Optional[List[SSMMetadataPair]]

class SSMControlSet(BaseModel):
    uri: str
    proposed: bool
    work_in_progress: bool
    label: str

class SSMControlStrategy(BaseModel):
    uri: str
    type: str
    description: str
    control_sets: Dict[str, SSMControlSet]

class SSMThreat(BaseModel):
    uri: str
    type: str
    id: str
    #control_strategies: Dict[str, SSMControlStrategy]
    control_strategies: Dict[str, str]

class SSMMisbehaviourSet(BaseModel):
    uri: str
    risk: str
    visible: bool
    impact_level: str
    located_at: str
    caused_threats: str
    misbehaviour: str
    label: str
    description: str
    risk_level: str
    visible: str

class SSMMisbehaviourDM(BaseModel):
    uri: str
    risk: str
    description: str

class ModelSummary(BaseModel):
    uri: str
    label: str
    description: str
    type: str
    parent: str
    id: str
    risk: str
    version_info: str
    domain_version: str
    created: str
    modified: str

class SSMDynamicModel(BaseModel):
    model: ModelSummary
    #threats: Dict[str, SSMThreat]
    #misbehaviour_sets: Dict[str SSMMisbehaviourSet]


class SSMModel():
    web_key: str = ""
    assets: Dict[str, SSMAsset] = {}
    threats: Dict[str, SSMThreat] = {}
    misbehaviour_sets: Dict[str, SSMMisbehaviourSet] = {}
    misbehavours: Dict[str, SSMMisbehaviourDM] = {}
    control_sets: Dict[str, SSMControlSet] = {}
    control_strategies: Dict[str, SSMControlStrategy] = {}
    stats: Dict[str, str] = {}

    def __init__(self, web_key):
        self.web_key = web_key




