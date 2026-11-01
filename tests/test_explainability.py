"""
Test Suite for CyberVision Explainable AI (XAI) and Narrative Generator.
Tests:
- NarrativeGenerator offline fallback and formatting
- CyberVisionExplainer TreeSHAP output shape and types
"""

import numpy as np
import pytest
from src.explainability.narrative_generator import NarrativeGenerator
from src.explainability.explainer import CyberVisionExplainer
import xgboost as xgb


def test_narrative_generator_formatting():
    gen = NarrativeGenerator()
    card = gen.generate_explanation_card(
        alert_id="ALT-2026-9999",
        attack_category="PortScan",
        confidence=0.985,
        severity="Critical",
        risk_score=94.5,
        top_shap_features=[
            {"feature": "flow_pkts_s", "sample_value": 1500.0, "baseline_median": 30.0, "shap_value": 0.38},
            {"feature": "syn_flag_cnt", "sample_value": 15.0, "baseline_median": 1.0, "shap_value": 0.25}
        ],
        mitre_technique_id="T1046"
    )

    assert card["alert_id"] == "ALT-2026-9999"
    assert card["confidence_pct"] == 98.5
    assert card["severity"] == "Critical"
    assert "T1046" in card["narrative"]
    assert "PortScan" in card["narrative"]


def test_narrative_generator_brief():
    gen = NarrativeGenerator()
    alert_info = {
        "alert_id": "ALT-2026-9999",
        "attack_category": "PortScan",
        "severity": "High",
        "risk_score": 85.0,
        "confidence_pct": 98.0,
        "mitre_technique_id": "T1046",
        "trigger_features": []
    }
    brief = gen.generate_ai_analyst_brief(alert_info)
    assert isinstance(brief, str)
    assert len(brief) > 50


def test_cybervision_explainer():
    rng = np.random.RandomState(42)
    X = rng.randn(100, 8).astype(np.float32)
    y = rng.choice([0, 1], size=100)

    model = xgb.XGBClassifier(n_estimators=10, max_depth=3, random_state=42)
    model.fit(X, y)

    feature_names = [f"feat_{i}" for i in range(8)]
    explainer = CyberVisionExplainer(
        model=model,
        feature_names=feature_names,
        background_data=X[:20]
    )

    sv, lat = explainer.explain_instance_treeshap(X[0])
    assert sv.shape == (8,)
    assert lat > 0.0

