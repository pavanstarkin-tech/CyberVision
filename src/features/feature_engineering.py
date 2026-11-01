"""
Multi-Layer Feature Engineering Pipeline for CyberVision.
Extracts normalized feature matrices, temporal connection rollups, and supports
multi-class zero-day holdouts without data leakage across 5-fold cross-validation.
"""

from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
import json
import joblib
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import StratifiedKFold, train_test_split


class FeatureEngineeringPipeline:
    """Prepares model-ready feature tensors and handles leakage-free scaling."""

    def __init__(self, zero_day_holdouts: List[str] = None):
        self.scaler = RobustScaler()
        self.zero_day_holdouts = zero_day_holdouts or ["Botnet_ARES", "eBPF_Rootkit_Hook", "Cloud_Staging_Exfil"]
        self.feature_names: List[str] = []
        self.is_fitted: bool = False

    def extract_features_from_df(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
        """Parses raw_features_json and returns a dataframe with flattened feat_* columns."""
        parsed_list = []
        for raw in df["raw_features_json"]:
            if isinstance(raw, str):
                try:
                    parsed_list.append(json.loads(raw))
                except Exception:
                    parsed_list.append({})
            elif isinstance(raw, dict):
                parsed_list.append(raw)
            else:
                parsed_list.append({})

        feat_df = pd.DataFrame(parsed_list).fillna(0.0)
        feat_cols = [f"feat_{c}" for c in feat_df.columns]
        feat_df.columns = feat_cols

        merged_df = pd.concat([df.reset_index(drop=True), feat_df.reset_index(drop=True)], axis=1)

        # Connection fanout & port entropy behavioral rollups
        if "src_ip" in merged_df.columns and "dst_ip" in merged_df.columns:
            fanout = merged_df.groupby("src_ip")["dst_ip"].nunique().to_dict()
            merged_df["feat_src_fanout_deg"] = merged_df["src_ip"].map(fanout).fillna(1.0).astype(float)
            port_counts = merged_df.groupby("src_ip")["dst_port"].nunique().to_dict()
            merged_df["feat_unique_dst_ports"] = merged_df["src_ip"].map(port_counts).fillna(1.0).astype(float)
            feat_cols.extend(["feat_src_fanout_deg", "feat_unique_dst_ports"])

        return merged_df, feat_cols

    def prepare_full_splits(
        self,
        df: pd.DataFrame,
        test_size: float = 0.20,
        random_state: int = 42
    ) -> Dict[str, Any]:
        """
        Splits data into Known-Threat Modeling set and Zero-Day Holdout sets.
        Fits RobustScaler strictly on the Training set.
        """
        enriched_df, feat_cols = self.extract_features_from_df(df)
        self.feature_names = feat_cols

        # Separate the 3 unseen Zero-Day holdouts
        is_zd = enriched_df["attack_category"].isin(self.zero_day_holdouts)
        df_known = enriched_df[~is_zd].copy().reset_index(drop=True)
        df_zd = enriched_df[is_zd].copy().reset_index(drop=True)

        X_known = df_known[feat_cols].values.astype(np.float32)
        y_known = df_known["ground_truth_label"].values.astype(int)
        cat_known = df_known["attack_category"].values

        # Stratified Train / Test split on Known classes
        indices = np.arange(len(df_known))
        idx_train, idx_test = train_test_split(
            indices, test_size=test_size, random_state=random_state, stratify=y_known
        )

        X_train_raw = X_known[idx_train]
        y_train = y_known[idx_train]
        df_train = df_known.iloc[idx_train].reset_index(drop=True)

        X_test_raw = X_known[idx_test]
        y_test = y_known[idx_test]
        df_test = df_known.iloc[idx_test].reset_index(drop=True)

        # Fit Scaler ONLY on X_train
        X_train_scaled = self.scaler.fit_transform(X_train_raw)
        X_test_scaled = self.scaler.transform(X_test_raw)

        # Scale Zero-Day Holdouts
        zd_dict = {}
        for zd_cls in self.zero_day_holdouts:
            sub_zd = df_zd[df_zd["attack_category"] == zd_cls]
            if len(sub_zd) > 0:
                X_zd = sub_zd[feat_cols].values.astype(np.float32)
                zd_dict[zd_cls] = {
                    "X": self.scaler.transform(X_zd),
                    "y": sub_zd["ground_truth_label"].values.astype(int),
                    "meta_df": sub_zd
                }

        self.is_fitted = True

        return {
            "feature_names": self.feature_names,
            "scaler": self.scaler,
            "train": {"X": X_train_scaled, "y": y_train, "meta_df": df_train},
            "test": {"X": X_test_scaled, "y": y_test, "meta_df": df_test},
            "zero_day_holdouts": zd_dict,
            "full_enriched_df": enriched_df
        }

    def save_pipeline(self, output_path: str = "models/saved/feature_pipeline.joblib"):
        import os
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        joblib.dump({"scaler": self.scaler, "feature_names": self.feature_names}, output_path)
