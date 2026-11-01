"""
Test Suite for CyberVision Cross-Layer Correlation Engine & Scenario Builder.
Tests:
- ScenarioBuilder generation of multi-stage attack campaigns
- CrossLayerCorrelationEngine entity graph linkage and AFR% computation
- Separation of unrelated events (preventing false clustering)
- ResponsePlaybookEngine matching
"""

import pytest
from src.correlation.scenario_builder import ScenarioBuilder
from src.correlation.correlation_engine import CrossLayerCorrelationEngine
from src.correlation.playbook_engine import ResponsePlaybookEngine


def test_scenario_builder():
    campaign_alerts, gt_campaigns = ScenarioBuilder.build_50_attack_campaigns(n_campaigns=5, n_background_noise=20)
    assert len(gt_campaigns) == 5
    assert len(campaign_alerts) == 5 * 3 + 20

    # Verify 3 stages exist
    stages = set(a.get("stage") for a in campaign_alerts if "stage" in a)
    assert {1, 2, 3}.issubset(stages)


def test_correlation_engine():
    campaign_alerts, gt_campaigns = ScenarioBuilder.build_50_attack_campaigns(n_campaigns=5, n_background_noise=20)
    engine = CrossLayerCorrelationEngine(time_window_minutes=30)

    incidents = engine.correlate_alerts(campaign_alerts)
    assert isinstance(incidents, list)
    assert len(incidents) > 0

    # Ensure alert reduction occurs (AFR > 0)
    afr = (1.0 - (len(incidents) / len(campaign_alerts))) * 100.0
    assert afr > 0.0

    # Test evaluation metrics
    metrics = engine.evaluate_campaign_correlation(campaign_alerts, incidents, gt_campaigns)
    assert "afr_pct" in metrics
    assert "fasr_pct" in metrics
    assert "chain_completeness_pct" in metrics
    assert metrics["chain_completeness_pct"] > 50.0


def test_unrelated_events_not_grouped():
    """Verify unrelated events with no shared entities/temporal proximity remain distinct."""
    unrelated_alerts = [
        {
            "event_id": "ev-isolated-alpha",
            "timestamp": "2026-11-01T08:00:00Z",
            "layer_source": "network",
            "src_ip": "1.1.1.1",
            "dst_ip": "10.0.0.1",
            "host_id": "srv-alpha",
            "user_id": "system",
            "hybrid_confidence": 0.90,
            "attack_category": "PortScan",
            "mitre_technique_id": "T1046"
        },
        {
            "event_id": "ev-isolated-beta",
            "timestamp": "2026-11-01T18:00:00Z",  # 10 hours later
            "layer_source": "host",
            "src_ip": "2.2.2.2",
            "dst_ip": "10.0.0.99",
            "host_id": "srv-beta",
            "user_id": "alice",
            "hybrid_confidence": 0.92,
            "attack_category": "Kernel_PrivEsc_Setuid",
            "mitre_technique_id": "T1548"
        }
    ]
    engine = CrossLayerCorrelationEngine(time_window_minutes=15)
    incidents = engine.correlate_alerts(unrelated_alerts)

    # Must produce 2 separate incidents, not 1 merged incident
    assert len(incidents) == 2
    inc1_events = [a["event_id"] for a in incidents[0]["alerts"]]
    inc2_events = [a["event_id"] for a in incidents[1]["alerts"]]
    assert set(inc1_events).isdisjoint(set(inc2_events))


def test_playbook_selection():
    pb_recon = ResponsePlaybookEngine.get_playbook_for_alert("T1046")
    assert pb_recon["mitre_id"] == "T1046"
    assert "Port Scan" in pb_recon["name"]

    pb_priv = ResponsePlaybookEngine.get_playbook_for_alert("T1548")
    assert pb_priv["mitre_id"] == "T1548"
    assert "Privilege Escalation" in pb_priv["name"]

    pb_def = ResponsePlaybookEngine.get_playbook_for_alert("T9999", "Unknown Attack")
    assert pb_def["playbook_id"] == "PB-GEN-99"
