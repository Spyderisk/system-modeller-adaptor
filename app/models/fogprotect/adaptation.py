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


from typing import Optional, List, Union, Any
from pydantic import BaseModel
from enum import Enum

from app.models.risk import RiskVector

def to_camel(string: str) -> str:
    return ''.join(word.capitalize() for word in string.split('_'))

class RiskLevel(BaseModel):
    overall_risk_level: str
    risk_vector: RiskVector

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AdaptationRisk(BaseModel):
    adaptation_proposal_id: int
    risk_level: RiskLevel

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AsIsRisk(BaseModel):
    id: str
    risk_level: RiskLevel

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AdaptationResponse(BaseModel):
    as_is_risk: AsIsRisk
    acceptable_risk_level: str
    adaptation_risks: List[AdaptationRisk]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

#####################################


class TypeEnum(Enum):
    DATABASE = "Database"
    DATA_CONTROLLER = "DataController"
    DATA_FLOW = "DataFlow"
    DATA_SUBJECT = "DataSubject"
    DBMS = "DBMS"
    FOG_COMPUTE = "FogCompute"
    IO_T_DEVICE = "IoTDevice"
    PRIVATE_SPACE = "PrivateSpace"
    RECORD = "Record"
    SOFTWARE_COMPONENT = "SoftwareComponent"
    STORED_DATA_SET = "StoredDataSet"

class BelongsTo(BaseModel):
    type: str
    referencedObjectID: str

class ToscaNodesRoot(BaseModel):
    type: str
    atid: str
    name: str
    id: int
    #tosca_nodes_root_id: int
    hosts: Optional[List[BelongsTo]]
    jurisdiction: Optional[str]
    usage_cost_per_day: Optional[float]
    capacity: Optional[int]
    transfer_cost_per_gb: Optional[float]
    cost_incurred: Optional[bool]
    compromised: Optional[bool]
    part_of: Union[List[BelongsTo], BelongsTo, None]
    hosted_on: Optional[BelongsTo]
    controlled_by: Optional[List[BelongsTo]]
    needed_capacity: Optional[int]
    has_to_be_deployed_on_fog_node: Optional[bool]
    transfer_by: Optional[List[BelongsTo]]
    stores: Optional[List[BelongsTo]]
    encrypted: Optional[bool]
    trust: Optional[List[BelongsTo]]
    location: Optional[str]
    owns: Optional[List[BelongsTo]]
    consists_of: Optional[List[BelongsTo]]
    disab: Optional[bool]
    amount_of_data_in_gb: Optional[float]
    transfers_to: Optional[List[BelongsTo]]
    connection_type: Optional[str]
    stored_in: Optional[BelongsTo]
    sensitive: Optional[bool]
    belongs_to: Optional[BelongsTo]
    personal: Optional[bool]
    trustworthy: Optional[str]
    controls: Optional[List[BelongsTo]]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class UDEModel(BaseModel):
    type: str
    atid: str
    tosca_nodes_root: List[ToscaNodesRoot]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


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
    type: str
    atid: str

class ChangesMadeToAsIsModel(BaseModel):
    object_to_identify: ObjectToIdentify
    changes: List[Change]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AsIsModel(BaseModel):
    type: str
    atid: str
    tosca_nodes_root: List[ToscaNodesRoot]

class AsIs(BaseModel):
    as_is_model: AsIsModel
    old_as_is_model: AsIsModel
    changes_made_to_as_is_model: List[ChangesMadeToAsIsModel]
    risks: List[Any]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AdaptationProposal(BaseModel):
    i_d: str
    adaptation_proposal_model: UDEModel
    changes_made_to_as_is_model: List[ChangesMadeToAsIsModel]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AdaptationProposalsRequest(BaseModel):
    siea_task_id: str
    as_is_model: UDEModel
    adaptation_proposals: List[AdaptationProposal]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AdaptationExecutedRequest(BaseModel):
    notification_type: Optional[str]
    siea_task_id: str
    as_is: AsIs
    adaptations: List[Any]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class ResetControlsRequest(BaseModel):
    changes_made_to_as_is_model: List[ChangesMadeToAsIsModel]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

