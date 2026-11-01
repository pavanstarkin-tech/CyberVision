"""
Pydantic Request and Response Schemas for the CyberVision FastAPI Service.
Includes Authentication, Playbooks, Alerts, Incidents, and Explainability.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., description="Analyst username")
    password: str = Field(..., description="Analyst password")


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    analyst_name: str
    role: str
    tier: str
    expires_in_hours: int = 24


class AnalystProfile(BaseModel):
    username: str
    analyst_name: str
    role: str
    tier: str
    permissions: List[str]


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


class PlaybookResponse(BaseModel):
    playbook_id: str
    name: str
    mitre_id: str
    threat_category: str
    severity_default: str
    rationale: str
    safe_investigation_steps: List[str]
    containment_guidance: List[str]
    eradication_and_recovery: List[str]


class TriageActionRequest(BaseModel):
    incident_id: str
    analyst_username: str
    action: str = Field(..., description="'Investigate' | 'Approve Containment' | 'Mark False Positive' | 'Close'")
    notes: str = Field(..., description="Analyst justification notes")


class TriageActionResponse(BaseModel):
    status: str
    incident_id: str
    recorded_action: str
    timestamp: str
    analyst: str


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
    recommended_playbook: Optional[PlaybookResponse] = None
