"""
Unsupervised Anomaly and Zero-Day Threat Detector for CyberVision.
Implements PyOD Isolation Forest, ECOD, and a PyTorch Deep Reconstruction Autoencoder
trained strictly on benign baseline telemetry.
"""

from typing import Dict, Any, Optional
import os
import numpy as np
import joblib
from pyod.models.iforest import IForest
from pyod.models.ecod import ECOD
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


class PyTorchAutoencoder(nn.Module):
    """Deep Symmetric Reconstruction Autoencoder for anomaly detection."""

    def __init__(self, input_dim: int):
        super(PyTorchAutoencoder, self).__init__()
        # Encoder: input -> 64 -> 32 -> 16 (bottleneck)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
        )
        # Decoder: 16 -> 32 -> 64 -> input
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Linear(64, input_dim)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class UnsupervisedAnomalyDetector:
    """Trains and evaluates unsupervised models strictly on benign baselines."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.models: Dict[str, Any] = {}
        self.autoencoder: Optional[PyTorchAutoencoder] = None
        self.autoencoder_threshold: float = 0.5
        self.benign_max_error: float = 1.0

    def train_models(
        self,
        X_train_benign: np.ndarray,
        epochs: int = 15,
        batch_size: int = 64
    ) -> Dict[str, Any]:
        """Train Isolation Forest, ECOD, and PyTorch Autoencoder on benign samples only."""
        print(f"[*] Training Unsupervised Anomaly Detectors on {len(X_train_benign)} benign baselines...")

        # 1. Isolation Forest
        iforest = IForest(n_estimators=100, contamination=0.01, random_state=self.random_state, n_jobs=-1)
        iforest.fit(X_train_benign)
        self.models["iforest"] = iforest

        # 2. ECOD (Empirical Cumulative Distribution Functions for Outlier Detection)
        ecod = ECOD(contamination=0.01)
        ecod.fit(X_train_benign)
        self.models["ecod"] = ecod

        # 3. PyTorch Deep Autoencoder
        input_dim = X_train_benign.shape[1]
        self.autoencoder = PyTorchAutoencoder(input_dim)
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(self.autoencoder.parameters(), lr=1e-3, weight_decay=1e-5)

        tensor_x = torch.tensor(X_train_benign, dtype=torch.float32)
        dataset = TensorDataset(tensor_x)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        self.autoencoder.train()
        for epoch in range(epochs):
            total_loss = 0.0
            for batch in loader:
                inputs = batch[0]
                optimizer.zero_grad()
                outputs = self.autoencoder(inputs)
                loss = criterion(outputs, inputs)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

        # Compute benign baseline reconstruction error threshold (99th percentile)
        self.autoencoder.eval()
        with torch.no_grad():
            reconstructed = self.autoencoder(tensor_x)
            mse_errors = torch.mean((tensor_x - reconstructed) ** 2, dim=1).numpy()
            self.autoencoder_threshold = float(np.percentile(mse_errors, 99))
            self.benign_max_error = max(float(np.percentile(mse_errors, 99.5)), 1e-4)

        print(f"[+] Unsupervised models trained. Autoencoder threshold (99th percentile): {self.autoencoder_threshold:.4f}")
        return self.models

    def score_anomaly(self, X: np.ndarray, model_name: str = "iforest") -> np.ndarray:
        """
        Returns calibrated anomaly probability S_anom(x) in [0, 1].
        High values indicate behavioral deviations or potential zero-days.
        """
        if model_name == "iforest":
            model = self.models["iforest"]
            raw_scores = model.decision_function(X) # Higher = more abnormal in PyOD
            # Min-Max normalize with clipping to [0, 1]
            min_s, max_s = raw_scores.min(), raw_scores.max()
            if max_s > min_s:
                return np.clip((raw_scores - min_s) / (max_s - min_s), 0.0, 1.0)
            return np.zeros(len(X))

        elif model_name == "autoencoder":
            if self.autoencoder is None:
                raise ValueError("PyTorch Autoencoder has not been trained.")
            self.autoencoder.eval()
            tensor_x = torch.tensor(X, dtype=torch.float32)
            with torch.no_grad():
                reconstructed = self.autoencoder(tensor_x)
                mse_errors = torch.mean((tensor_x - reconstructed) ** 2, dim=1).numpy()
            # Normalize against benign 99th percentile
            norm_scores = np.clip(mse_errors / (self.benign_max_error * 1.5), 0.0, 1.0)
            return norm_scores

        else:
            model = self.models.get(model_name, self.models["ecod"])
            raw_scores = model.decision_function(X)
            min_s, max_s = raw_scores.min(), raw_scores.max()
            if max_s > min_s:
                return np.clip((raw_scores - min_s) / (max_s - min_s), 0.0, 1.0)
            return np.zeros(len(X))

    def save_models(self, directory: str = "models/saved"):
        """Save anomaly detectors and PyTorch weights."""
        os.makedirs(directory, exist_ok=True)
        for name in ["iforest", "ecod"]:
            if name in self.models:
                joblib.dump(self.models[name], os.path.join(directory, f"anomaly_{name}.joblib"))

        if self.autoencoder is not None:
            torch.save({
                "state_dict": self.autoencoder.state_dict(),
                "threshold": self.autoencoder_threshold,
                "benign_max_error": self.benign_max_error
            }, os.path.join(directory, "anomaly_autoencoder.pt"))

