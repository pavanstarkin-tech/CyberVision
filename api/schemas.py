"""
Pydantic Request and Response Schemas for the CyberVision FastAPI Service.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    """Batch ingestion request containing raw heterogeneous logs."""
    logs: List[Dict[str, Any]] = Field(..., description="List of raw log records")


class IngestResponse(BaseModel):
    status: str
    records_ingested: int
    sample_ids: List[str]


class DetectionRequest(BaseModel):
    """Detection request for feature vectors or normalized events."""
    events: List[Dict[str, Any]]


class DetectionAlert(BaseModel):
    event_id: str
    layer_source: str
    hybrid_confidence: float
    supervised_probability: float
    anomaly_score: float
    is_threat: bool
    attack_category: str
    mitre_technique_id: str
    severity: str
    risk_score: float


class DetectionResponse(BaseModel):
    total_events: int
    threats_detected: int
    alerts: List[DetectionAlert]


class IncidentSummary(BaseModel):
    incident_id: str
    severity: str
    risk_score: float
    num_alerts: int
    num_layers_active: int
    corroborating_layers: List[str]
    peak_confidence: float
    cti_reputation: float
    cti_tags: List[str]
    associated_entities: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]


class ExplainResponse(BaseModel):
    alert_id: str
    attack_category: str
    confidence_pct: float
    severity: str
    risk_score: float
    mitre_technique_id: str
    narrative: str
    shap_top_features: List[Dict[str, Any]]
    lime_rules: List[Dict[str, Any]]
    cti_intel: Dict[str, Any]

