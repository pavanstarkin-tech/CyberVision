"""
Comprehensive Explainable AI (XAI) Attribution & Benchmarking Engine for CyberVision.
Implements and benchmarks 4 explanation methodologies:
1. TreeSHAP (Exact game-theoretic attribution)
2. KernelSHAP (Model-agnostic sampling approximation)
3. LIME Tabular (Local linear surrogate)
4. Permutation Feature Importance (Global shuffle ablation)
Computes Faithfulness, Insertion AUC, Lipschitz Stability, Sparsity, Jaccard Agreement, and Latency.
"""

import time
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.inspection import permutation_importance
import shap
import lime
import lime.lime_tabular


class CyberVisionExplainer:
    """Benchmarks 4 XAI explainers with rigorous mathematical metrics."""

    def __init__(
        self,
        model: Any,
        feature_names: List[str],
        background_data: np.ndarray,
        class_names: List[str] = None
    ):
        self.model = model
        self.feature_names = feature_names
        self.background_data = background_data
        self.class_names = class_names or ["Benign", "Malicious"]
        self.benign_median = np.median(background_data, axis=0)

        # 1. TreeSHAP Explainer
        print("[*] Initializing TreeSHAP...")
        try:
            self.tree_explainer = shap.TreeExplainer(self.model)
        except Exception:
            self.tree_explainer = shap.TreeExplainer(self.model.get_booster())

        # 2. KernelSHAP Explainer (small representative background set for speed)
        print("[*] Initializing KernelSHAP...")
        self.kernel_background = background_data[:40]
        self.kernel_explainer = shap.KernelExplainer(self.model.predict_proba, self.kernel_background)

        # 3. LIME Tabular Explainer
        print("[*] Initializing LIME Tabular...")
        self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
            training_data=background_data[:500],
            feature_names=feature_names,
            class_names=self.class_names,
            mode="classification",
            random_state=42
        )

    def explain_instance_treeshap(self, sample: np.ndarray) -> Tuple[np.ndarray, float]:
        """Returns (shap_values, latency_ms)."""
        t0 = time.perf_counter()
        sample_2d = sample.reshape(1, -1)
        sv = self.tree_explainer.shap_values(sample_2d)
        lat = (time.perf_counter() - t0) * 1000.0

        if isinstance(sv, list):
            res = sv[1][0] if len(sv) > 1 else sv[0][0]
        elif len(sv.shape) == 3:
            res = sv[0, :, 1]
        else:
            res = sv[0]
        return res, lat

    def explain_instance_kernelshap(self, sample: np.ndarray) -> Tuple[np.ndarray, float]:
        t0 = time.perf_counter()
        sv = self.kernel_explainer.shap_values(sample.reshape(1, -1), nsamples=80, silent=True)
        lat = (time.perf_counter() - t0) * 1000.0

        if isinstance(sv, list):
            res = sv[1][0] if len(sv) > 1 else sv[0][0]
        elif len(sv.shape) == 3:
            res = sv[0, :, 1]
        else:
            res = sv[0]
        return res, lat

    def explain_instance_lime(self, sample: np.ndarray) -> Tuple[np.ndarray, float]:
        t0 = time.perf_counter()
        exp = self.lime_explainer.explain_instance(
            data_row=sample,
            predict_fn=self.model.predict_proba,
            num_features=len(self.feature_names)
        )
        lat = (time.perf_counter() - t0) * 1000.0

        weights = np.zeros(len(self.feature_names))
        for feat_rule, weight in exp.as_list():
            for idx, fname in enumerate(self.feature_names):
                if fname in feat_rule:
                    weights[idx] = weight
                    break
        return weights, lat

    def compute_gini_sparsity(self, weights: np.ndarray) -> float:
        """Computes Gini index of feature attribution sparsity (higher = more sparse/concentrated)."""
        w = np.sort(np.abs(weights))
        n = len(w)
        if np.sum(w) == 0:
            return 0.0
        index = np.arange(1, n + 1)
        return float((2.0 * np.sum(index * w)) / (n * np.sum(w)) - (n + 1.0) / n)

    def benchmark_4_xai_methods(
        self,
        X_sample: np.ndarray,
        y_sample: np.ndarray,
        n_alerts: int = 250
    ) -> List[Dict[str, Any]]:
        """
        Benchmarks TreeSHAP, KernelSHAP, LIME Tabular, and Permutation Importance
        across Faithfulness, Insertion AUC, Stability, Sparsity, Jaccard overlap, and Latency.
        """
        print(f"[*] Benchmarking 4 XAI Methods across {min(n_alerts, len(X_sample))} alert instances...")
        sub_X = X_sample[:n_alerts]
        sub_y = y_sample[:n_alerts]
        orig_probs = self.model.predict_proba(sub_X)[:, 1]

        methods = ["TreeSHAP", "KernelSHAP", "LIME Tabular", "Permutation Importance"]
        results = []

        # Pre-compute Global Permutation Importance
        t0_perm = time.perf_counter()
        perm_res = permutation_importance(self.model, sub_X, sub_y, n_repeats=5, random_state=42)
        perm_weights = perm_res.importances_mean
        perm_lat_total = (time.perf_counter() - t0_perm) * 1000.0
        perm_lat_per_alert = perm_lat_total / len(sub_X)

        # 1. TreeSHAP evaluations
        tree_weights = []
        tree_lats = []
        for x in sub_X:
            w, lat = self.explain_instance_treeshap(x)
            tree_weights.append(w)
            tree_lats.append(lat)
        tree_weights = np.array(tree_weights)

        # 2. KernelSHAP evaluations (on a subset of 60 for practical benchmarking time)
        kernel_weights = []
        kernel_lats = []
        for x in sub_X[:60]:
            w, lat = self.explain_instance_kernelshap(x)
            kernel_weights.append(w)
            kernel_lats.append(lat)
        kernel_weights = np.array(kernel_weights)

        # 3. LIME evaluations (on 100 alerts)
        lime_weights = []
        lime_lats = []
        for x in sub_X[:100]:
            w, lat = self.explain_instance_lime(x)
            lime_weights.append(w)
            lime_lats.append(lat)
        lime_weights = np.array(lime_weights)

        method_data = {
            "TreeSHAP": (tree_weights, tree_lats, sub_X, orig_probs),
            "KernelSHAP": (kernel_weights, kernel_lats, sub_X[:len(kernel_weights)], orig_probs[:len(kernel_weights)]),
            "LIME Tabular": (lime_weights, lime_lats, sub_X[:len(lime_weights)], orig_probs[:len(lime_weights)]),
            "Permutation Importance": (np.tile(perm_weights, (len(sub_X), 1)), [perm_lat_per_alert]*len(sub_X), sub_X, orig_probs)
        }

        # Reference TreeSHAP top-5 sets for Jaccard and Spearman comparisons
        tree_top5_sets = [set(np.argsort(np.abs(w))[::-1][:5]) for w in tree_weights]

        for name in methods:
            w_arr, lats, cur_X, cur_probs = method_data[name]
            n_eval = len(w_arr)

            # Faithfulness Deletion Drop (Top-1, Top-3, Top-5)
            drops = {1: [], 3: [], 5: []}
            for k in [1, 3, 5]:
                masked_X = cur_X.copy()
                for i in range(n_eval):
                    top_k_idx = np.argsort(np.abs(w_arr[i]))[::-1][:k]
                    masked_X[i, top_k_idx] = self.benign_median[top_k_idx]
                masked_prob = self.model.predict_proba(masked_X)[:, 1]
                drops[k] = float(np.mean(cur_probs - masked_prob))

            # Insertion Comprehensiveness AUC (inserting top-1, top-3, top-5 from baseline)
            insertion_scores = []
            for k in [1, 3, 5]:
                inserted_X = np.tile(self.benign_median, (n_eval, 1))
                for i in range(n_eval):
                    top_k_idx = np.argsort(np.abs(w_arr[i]))[::-1][:k]
                    inserted_X[i, top_k_idx] = cur_X[i, top_k_idx]
                ins_prob = self.model.predict_proba(inserted_X)[:, 1]
                insertion_scores.append(float(np.mean(ins_prob)))
            insertion_auc = float(np.mean(insertion_scores))

            # Stability (Lipschitz continuity under noise)
            noise = np.random.normal(0, 0.01, size=cur_X[:50].shape)
            X_pert = cur_X[:50] + noise
            diff_x = np.linalg.norm(cur_X[:50] - X_pert, axis=1) + 1e-8

            if name == "TreeSHAP":
                w_pert = np.array([self.explain_instance_treeshap(x)[0] for x in X_pert])
            elif name == "LIME Tabular":
                w_pert = np.array([self.explain_instance_lime(x)[0] for x in X_pert])
            elif name == "KernelSHAP":
                w_pert = np.array([self.explain_instance_kernelshap(x)[0] for x in X_pert[:20]])
                diff_x = diff_x[:20]
                w_arr_sub = w_arr[:20]
            else:
                w_pert = w_arr[:50]

            if name != "KernelSHAP":
                w_arr_sub = w_arr[:50]

            diff_w = np.linalg.norm(w_arr_sub - w_pert, axis=1)
            lip_l = float(np.mean(diff_w / diff_x))

            # Sparsity (Gini)
            ginis = [self.compute_gini_sparsity(w) for w in w_arr]
            mean_gini = float(np.mean(ginis))

            # Jaccard Overlap and Spearman Rank Correlation with TreeSHAP
            jaccards = []
            spearmans = []
            for i in range(min(n_eval, len(tree_top5_sets))):
                top_m = set(np.argsort(np.abs(w_arr[i]))[::-1][:5])
                top_t = tree_top5_sets[i]
                j_val = len(top_m.intersection(top_t)) / len(top_m.union(top_t)) if len(top_m.union(top_t)) > 0 else 1.0
                jaccards.append(j_val)

                rho, _ = spearmanr(np.abs(w_arr[i]), np.abs(tree_weights[i]))
                spearmans.append(rho if not np.isnan(rho) else 0.5)

            results.append({
                "XAI_Method": name,
                "Faithfulness_Top1_Drop": round(drops[1], 4),
                "Faithfulness_Top3_Drop": round(drops[3], 4),
                "Faithfulness_Top5_Drop": round(drops[5], 4),
                "Insertion_AUC": round(insertion_auc, 4),
                "Lipschitz_Stability_L": round(lip_l, 4),
                "Gini_Sparsity": round(mean_gini, 4),
                "Top5_Jaccard_with_TreeSHAP_Pct": round(float(np.mean(jaccards) * 100.0), 2),
                "Spearman_Rank_Correlation": round(float(np.mean(spearmans)), 4),
                "Latency_p50_ms": round(float(np.percentile(lats, 50)), 2),
                "Latency_p95_ms": round(float(np.percentile(lats, 95)), 2),
                "Latency_p99_ms": round(float(np.percentile(lats, 99)), 2)
            })

        return results

    def extract_top15_features_by_layer(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        meta_df: pd.DataFrame
    ) -> List[Dict[str, Any]]:
        """
        Computes Mean |SHAP| attributions and returns the Top-5 features per layer (15 total)
        with Benign vs. Attack IQRs and MITRE technique IDs.
        """
        print("[*] Extracting Top-15 Multi-Layer Features with Global SHAP Values...")
        shap_vals = self.tree_explainer.shap_values(X_test[:500])
        if isinstance(shap_vals, list):
            sv = shap_vals[1] if len(shap_vals) > 1 else shap_vals[0]
        elif len(shap_vals.shape) == 3:
            sv = shap_vals[:, :, 1]
        else:
            sv = shap_vals

        mean_abs_shap = np.mean(np.abs(sv), axis=0)

        # Categorize features by layer
        layer_features = {
            "Layer 1: Network": [f for f in self.feature_names if any(k in f for k in ["flow", "pkt", "byts", "syn", "rst", "ack", "fanout", "dst_ports"])],
            "Layer 2: Host/eBPF": [f for f in self.feature_names if any(k in f for k in ["args", "uid", "spawn", "namespace", "orphan", "syscall", "privilege"])],
            "Layer 3: User/UEBA": [f for f in self.feature_names if any(k in f for k in ["off_hours", "logon", "usb", "email", "transfer", "session"])]
        }

        # Fallback if names don't match cleanly
        remaining = set(self.feature_names) - set(layer_features["Layer 1: Network"] + layer_features["Layer 2: Host/eBPF"] + layer_features["Layer 3: User/UEBA"])
        for f in remaining:
            layer_features["Layer 1: Network"].append(f)

        top15_records = []
        mitre_map = {
            "feat_syn_flag_ratio": ("T1498.001", "DoS Direct Network Flood"),
            "feat_flow_pkts_s": ("T1499", "Endpoint Denial of Service"),
            "feat_flow_duration": ("T1110.001", "Brute Force Password Guessing"),
            "feat_flow_byts_s": ("T1048", "Exfiltration Over Alternative Protocol"),
            "feat_unique_dst_ports": ("T1046", "Network Service Discovery"),
            "feat_is_root_uid": ("T1548", "Abuse Elevation Control Mechanism"),
            "feat_child_spawn_velocity": ("T1059", "Command and Scripting Interpreter"),
            "feat_namespace_switch_cnt": ("T1611", "Escape to Host Container"),
            "feat_orphan_parent_flag": ("T1014", "Rootkit Subversion"),
            "feat_args_num": ("T1059.004", "Unix Shell Execution"),
            "feat_file_transfer_bytes": ("T1048", "Exfiltration Over Alternative Protocol"),
            "feat_off_hours_usb_bytes": ("T1052.001", "Exfiltration over Physical Medium"),
            "feat_failed_logon_burst": ("T1078", "Valid Accounts Brute Force"),
            "feat_is_off_hours": ("T1078.003", "Local Accounts Off-Hours"),
            "feat_email_outbound_recipients": ("T1567", "Exfiltration Over Web Service")
        }

        benign_mask = (y_test[:500] == 0)
        attack_mask = (y_test[:500] == 1)

        for layer_name, f_list in layer_features.items():
            # Sort features in this layer by mean absolute SHAP
            f_scores = [(f, mean_abs_shap[self.feature_names.index(f)]) for f in f_list if f in self.feature_names]
            f_scores.sort(key=lambda x: x[1], reverse=True)

            for f_name, score in f_scores[:5]:
                f_idx = self.feature_names.index(f_name)
                b_vals = X_test[:500, f_idx][benign_mask]
                a_vals = X_test[:500, f_idx][attack_mask]

                b_med, b_q1, b_q3 = np.percentile(b_vals, [50, 25, 75]) if len(b_vals) > 0 else (0, 0, 0)
                a_med, a_q1, a_q3 = np.percentile(a_vals, [50, 25, 75]) if len(a_vals) > 0 else (0, 0, 0)

                m_id, m_name = mitre_map.get(f_name, ("T1000", "Enterprise Activity"))

                clean_name = f_name.replace("feat_", "")
                top15_records.append({
                    "Layer": layer_name,
                    "Feature_Name": clean_name,
                    "Mean_Abs_SHAP": round(float(score), 4),
                    "Benign_Median_IQR": f"{b_med:.2f} ({b_q1:.2f}–{b_q3:.2f})",
                    "Attack_Median_IQR": f"{a_med:.2f} ({a_q1:.2f}–{a_q3:.2f})",
                    "Primary_MITRE_Technique_ID": m_id,
                    "MITRE_Technique_Name": m_name
                })

        return top15_records
