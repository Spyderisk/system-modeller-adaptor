from typing import Optional, List
from pydantic import BaseModel

from app.models.risk import RiskVector
from app.models.protego.recommendations import Recommendation

def to_camel(string: str) -> str:
    return ''.join(word.capitalize() for word in string.split('_'))

class ObjectToIdentify(BaseModel):
    name: str
    atid: str
    type: Optional[str]

class Risk(BaseModel):
    object_to_identify: ObjectToIdentify
    risk_description: str
    risk_impact: str
    risk_name: str
    risk_likelihood: str
    risk_level: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class RiskLevel(BaseModel):
    overall_risk_level: str
    risk_vector: RiskVector

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AdaptationRisk(BaseModel):
    adaptation_proposal_id: str
    risk_level: RiskLevel

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class AsIsRisk(BaseModel):
    at_id: str
    risk_level: RiskLevel

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True


class ImmediateAction(BaseModel):
    notification_type: str
    event_name: str
    siea_task_id: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class ResultOfRiskCalculation(BaseModel):
    siea_task_id: str
    notification_type: str
    acceptable_risk_level: str
    overall_risk_level: str
    risk_vector: RiskVector
    risks: List[Risk]
    recommendations: Optional[List[Recommendation]]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class EvaluationOfAdaptationProposals(BaseModel):
    notification_type: str
    as_is_risk: AsIsRisk
    acceptable_risk_level: str
    adaptation_risks: List[AdaptationRisk]
    siea_task_id: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class EvaluationOfAdaptation(BaseModel):
    notification_type: str
    as_is_risk: AsIsRisk
    acceptable_risk_level: str
    adaptation_risk: AdaptationRisk
    siea_task_id: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class EventNotification(BaseModel):
    notification_type: str
    event_name: Optional[str]
    risks: Optional[List[Risk]]
    overall_risk_level: Optional[str]
    risk_vector: Optional[RiskVector]
    acceptable_risk_level: Optional[str]
    as_is_risk: Optional[AsIsRisk]
    adaptation_risks: Optional[List[AdaptationRisk]]
    adaptation_risk: Optional[AdaptationRisk]
    siea_task_id: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True
