"""
Test Suite for CyberVision REST API Endpoints.
Tests:
- GET  /health
- POST /api/v1/auth/login (Success & Failure)
- GET  /api/v1/auth/me
- POST /api/v1/ingest (Success & Input Validation)
- POST /api/v1/detect
- GET  /api/v1/alerts (Search & Filters)
- GET  /api/v1/incidents
- POST /api/v1/incidents/triage (Audit trail logging)
- GET  /api/v1/playbooks/{technique_id}
- GET  /api/v1/explain/{alert_id}
"""

import pytest
from fastapi.testclient import TestClient
from api.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert data["db_records"] >= 0


def test_auth_login_and_me(client):
    # Test valid credentials
    login_res = client.post("/api/v1/auth/login", json={
        "username": "analyst1",
        "password": "cybervision2026"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "access_token" in login_data
    assert login_data["role"] == "Tier-1 Analyst"

    token = login_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "analyst1"

    # Test invalid credentials
    bad_res = client.post("/api/v1/auth/login", json={
        "username": "analyst1",
        "password": "wrong_password"
    })
    assert bad_res.status_code == 401


def test_ingest_endpoint(client):
    payload = {
        "logs": [
            {
                "layer_source": "network",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.5",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "flow_duration": 1200,
                "flow_pkts_s": 45.2
            },
            {
                "layer_source": "host",
                "host_id": "srv-db-01",
                "user_id": "root",
                "process_name": "sudo",
                "process_id": 4120,
                "parent_process_id": 1001,
                "event_action": "privilege_escalation"
            }
        ]
    }
    res = client.post("/api/v1/ingest", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["records_ingested"] == 2
    assert len(data["sample_ids"]) == 2


def test_input_validation_invalid_data(client):
    # Missing required 'logs' field
    res = client.post("/api/v1/ingest", json={"invalid_field": 123})
    assert res.status_code == 422


def test_detect_endpoint(client):
    payload = {
        "events": [
            {
                "event_id": "test-alert-001",
                "layer_source": "network",
                "attack_category": "PortScan",
                "mitre_technique_id": "T1046",
                "supervised_prob": 0.94,
                "anomaly_score": 0.82
            },
            {
                "event_id": "test-alert-002",
                "layer_source": "network",
                "attack_category": "Benign",
                "mitre_technique_id": "N/A",
                "supervised_prob": 0.05,
                "anomaly_score": 0.10
            }
        ]
    }
    res = client.post("/api/v1/detect", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] == 2
    assert data["threats_detected"] >= 1
    assert len(data["alerts"]) == 2

    threat_alert = data["alerts"][0]
    assert threat_alert["event_id"] == "test-alert-001"
    assert threat_alert["is_threat"] is True
    assert threat_alert["severity"] in ["High", "Critical"]


def test_alerts_search_and_filter(client):
    res = client.get("/api/v1/alerts?limit=10&is_synthetic=0")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert data["total_returned"] >= 0


def test_incidents_endpoint(client):
    res = client.get("/api/v1/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert isinstance(incidents, list)
    assert len(incidents) > 0
    sample = incidents[0]
    assert "incident_id" in sample
    assert "severity" in sample
    assert "risk_score" in sample
    assert "num_layers_active" in sample


def test_playbooks_endpoint(client):
    res = client.get("/api/v1/playbooks/T1046")
    assert res.status_code == 200
    pb = res.json()
    assert pb["mitre_id"] == "T1046"
    assert len(pb["safe_investigation_steps"]) > 0
    assert len(pb["containment_guidance"]) > 0


def test_triage_action_recording(client):
    payload = {
        "incident_id": "INC-2026-0001",
        "analyst_username": "analyst1",
        "action": "Approve Containment",
        "notes": "Verified SSH brute-force attack progression. Approved temporary ACL block."
    }
    res = client.post("/api/v1/incidents/triage", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "Recorded"
    assert data["incident_id"] == "INC-2026-0001"


def test_explain_endpoint(client):
    res = client.get("/api/v1/explain/test-alert-001")
    assert res.status_code == 200
    data = res.json()
    assert data["alert_id"] == "test-alert-001"
    assert "narrative" in data
    assert len(data["narrative"]) > 20
    assert len(data["shap_top_features"]) > 0
    assert "cti_intel" in data
    assert "recommended_playbook" in data
