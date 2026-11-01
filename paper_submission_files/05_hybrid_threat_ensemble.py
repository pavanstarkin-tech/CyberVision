"""
Multi-Model Hybrid Threat Ensemble for CyberVision.
Blends Supervised Gradient Boosting (XGBoost + LightGBM) with Unsupervised Anomaly
Detection (PyTorch Deep Autoencoder + Isolation Forest):
P_hybrid(x) = alpha * P_sup_ens(x) + (1 - alpha) * S_anom_ens(x)
"""

from typing import Dict, Any, Tuple
import numpy as np

from src.models.supervised_detector import SupervisedThreatDetector
from src.models.anomaly_detector import UnsupervisedAnomalyDetector


class HybridThreatEnsemble:
    """Multi-Model Hybrid Ensemble with flexible fusion weights and zero-day sensitivity."""

    def __init__(
        self,
        supervised_detector: SupervisedThreatDetector,
        anomaly_detector: UnsupervisedAnomalyDetector,
        alpha: float = 0.65
    ):
        self.supervised_detector = supervised_detector
        self.anomaly_detector = anomaly_detector
        self.alpha = alpha

    def predict_hybrid_score(
        self,
        X: np.ndarray,
        alpha: float = None
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Calculates hybrid threat confidence score:
        P_sup_ens = 0.5 * P_xgb + 0.5 * P_lgb
        S_anom_ens = 0.5 * S_iforest + 0.5 * S_autoencoder
        P_hybrid = alpha * P_sup_ens + (1 - alpha) * S_anom_ens
        """
        a = self.alpha if alpha is None else alpha

        # Supervised ensemble
        p_xgb = self.supervised_detector.predict_proba(X, "calibrated_xgboost")
        p_lgb = self.supervised_detector.predict_proba(X, "lightgbm")
        p_sup = 0.5 * p_xgb + 0.5 * p_lgb

        # Anomaly ensemble
        s_iforest = self.anomaly_detector.score_anomaly(X, "iforest")
        s_ae = self.anomaly_detector.score_anomaly(X, "autoencoder")
        s_anom = 0.5 * s_iforest + 0.5 * s_ae

        p_hybrid = (a * p_sup) + ((1.0 - a) * s_anom)
        p_hybrid = np.clip(p_hybrid, 0.0, 1.0)
        return p_hybrid, p_sup, s_anom

    def predict_binary(
        self,
        X: np.ndarray,
        threshold: float = 0.40,
        alpha: float = None
    ) -> np.ndarray:
        """Flags threat if hybrid score exceeds threshold OR strong anomaly indicates zero-day."""
        p_hybrid, p_sup, s_anom = self.predict_hybrid_score(X, alpha=alpha)
        is_threat = (p_hybrid >= threshold) | (s_anom >= 0.55)
        return is_threat.astype(int)
