"""
Test Suite for CyberVision Machine Learning and Anomaly Detection Models.
Tests:
- SupervisedThreatDetector
- UnsupervisedAnomalyDetector
- HybridThreatEnsemble fusion scoring
"""

import numpy as np
import pytest
from src.models.supervised_detector import SupervisedThreatDetector
from src.models.anomaly_detector import UnsupervisedAnomalyDetector
from src.models.hybrid_ensemble import HybridThreatEnsemble


@pytest.fixture(scope="module")
def synthetic_data():
    rng = np.random.RandomState(42)
    n_samples, n_features = 200, 15
    X = rng.randn(n_samples, n_features).astype(np.float32)
    y = rng.choice([0, 1], size=n_samples, p=[0.7, 0.3])
    return X, y


def test_supervised_detector(synthetic_data):
    X, y = synthetic_data
    detector = SupervisedThreatDetector()
    detector.train_models(X, y)

    # Test predictions from XGBoost and LightGBM
    p_xgb = detector.predict_proba(X, "xgboost")
    assert p_xgb.shape == (len(X),)
    assert np.all((p_xgb >= 0.0) & (p_xgb <= 1.0))

    p_lgb = detector.predict_proba(X, "lightgbm")
    assert p_lgb.shape == (len(X),)
    assert np.all((p_lgb >= 0.0) & (p_lgb <= 1.0))


def test_anomaly_detector(synthetic_data):
    X, y = synthetic_data
    X_benign = X[y == 0]
    anom_detector = UnsupervisedAnomalyDetector()
    anom_detector.train_models(X_benign, epochs=3)

    # Score anomaly with Isolation Forest
    s_if = anom_detector.score_anomaly(X, "iforest")
    assert s_if.shape == (len(X),)
    assert np.all((s_if >= 0.0) & (s_if <= 1.0))

    # Score anomaly with PyTorch Autoencoder
    s_ae = anom_detector.score_anomaly(X, "autoencoder")
    assert s_ae.shape == (len(X),)
    assert np.all((s_ae >= 0.0) & (s_ae <= 1.0))


def test_hybrid_ensemble(synthetic_data):
    X, y = synthetic_data
    sup_det = SupervisedThreatDetector()
    sup_det.train_models(X, y)

    anom_det = UnsupervisedAnomalyDetector()
    anom_det.train_models(X[y == 0], epochs=2)

    ensemble = HybridThreatEnsemble(supervised_detector=sup_det, anomaly_detector=anom_det, alpha=0.65)
    p_hyb, p_sup, s_anom = ensemble.predict_hybrid_score(X)

    assert p_hyb.shape == (len(X),)
    assert np.all((p_hyb >= 0.0) & (p_hyb <= 1.0))

    preds = ensemble.predict_binary(X, threshold=0.40)
    assert preds.shape == (len(X),)
    assert set(np.unique(preds)).issubset({0, 1})
