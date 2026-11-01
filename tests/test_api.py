"""
Test Suite for CyberVision REST API Endpoints.
Tests:
- GET  /health
- POST /api/v1/ingest
- POST /api/v1/detect
- GET  /api/v1/incidents
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


def test_explain_endpoint(client):
    res = client.get("/api/v1/explain/test-alert-001")
    assert res.status_code == 200
    data = res.json()
    assert data["alert_id"] == "test-alert-001"
    assert "narrative" in data
    assert len(data["narrative"]) > 20
    assert len(data["shap_top_features"]) > 0
    assert "cti_intel" in data

