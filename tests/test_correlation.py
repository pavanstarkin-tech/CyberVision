"""
Test Suite for CyberVision Cross-Layer Correlation Engine & Scenario Builder.
Tests:
- ScenarioBuilder generation of multi-stage attack campaigns
- CrossLayerCorrelationEngine entity graph linkage and AFR% computation
"""

import pytest
from src.correlation.scenario_builder import ScenarioBuilder
from src.correlation.correlation_engine import CrossLayerCorrelationEngine


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
