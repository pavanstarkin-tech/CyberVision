"""
Multi-Model Supervised Threat Detection Engine for CyberVision.
Implements Logistic Regression, Gaussian Naive Bayes, Random Forest, XGBoost, and LightGBM
with probability calibration.
"""

from typing import Dict, Any, Tuple
import os
import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
import xgboost as xgb
import lightgbm as lgb


class SupervisedThreatDetector:
    """Trains and serves calibrated supervised threat classifiers."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.models: Dict[str, Any] = {}

    def train_models(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray
    ) -> Dict[str, Any]:
        """Trains Logistic Regression, GaussianNB, Random Forest, XGBoost, and LightGBM."""
        print("[*] Training Supervised Classifiers across Known Threat Classes...")

        # 1. Baseline: Logistic Regression
        lr = LogisticRegression(max_iter=500, random_state=self.random_state)
        lr.fit(X_train, y_train)
        self.models["logistic_regression"] = lr

        # 2. Gaussian Naive Bayes
        gnb = GaussianNB()
        gnb.fit(X_train, y_train)
        self.models["gaussian_nb"] = gnb

        # 3. Random Forest
        rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=self.random_state, n_jobs=-1)
        rf.fit(X_train, y_train)
        self.models["random_forest"] = rf

        # 4. XGBoost
        xgb_clf = xgb.XGBClassifier(
            n_estimators=120,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            random_state=self.random_state,
            eval_metric="logloss",
            n_jobs=-1
        )
        xgb_clf.fit(X_train, y_train)
        self.models["xgboost"] = xgb_clf

        # 5. LightGBM
        lgb_clf = lgb.LGBMClassifier(
            n_estimators=120,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            random_state=self.random_state,
            verbose=-1,
            n_jobs=-1
        )
        lgb_clf.fit(X_train, y_train)
        self.models["lightgbm"] = lgb_clf

        # 6. Calibrated XGBoost
        calibrated_xgb = CalibratedClassifierCV(estimator=xgb_clf, method="sigmoid", cv=3)
        calibrated_xgb.fit(X_train, y_train)
        self.models["calibrated_xgboost"] = calibrated_xgb

        print("[+] All supervised models successfully trained.")
        return self.models

    def predict_proba(self, X: np.ndarray, model_name: str = "calibrated_xgboost") -> np.ndarray:
        """Returns predicted probability for malicious class P(y=1 | X)."""
        model = self.models.get(model_name, self.models.get("xgboost"))
        if model is None:
            raise ValueError(f"Model '{model_name}' is not trained.")
        probs = model.predict_proba(X)
        if probs.shape[1] == 2:
            return probs[:, 1]
        return probs

    def predict(self, X: np.ndarray, model_name: str = "calibrated_xgboost", threshold: float = 0.5) -> np.ndarray:
        prob = self.predict_proba(X, model_name)
        return (prob >= threshold).astype(int)

    def save_models(self, directory: str = "models/saved"):
        os.makedirs(directory, exist_ok=True)
        for name, model in self.models.items():
            joblib.dump(model, os.path.join(directory, f"supervised_{name}.joblib"))
