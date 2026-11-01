"""
Reproducible Empirical Latency & Throughput Measurement Script.
Measures:
1. Feature Extraction & Scaling
2. Supervised Inference (Model Only)
3. Anomaly Scoring (Model Only)
4. Hybrid Ensemble Inference (Model Only)
5. Full Ingestion & Detection Pipeline Latency
6. TreeSHAP Attribution Latency (Model Only) vs LIME Tabular Latency
7. NetworkX Temporal Graph Correlation Latency
8. SQLite CTI Cache Lookup Latency
9. Full End-to-End Automated Triage Latency
10. Pipeline Throughput (Events/sec)
"""

import time
import os
import duckdb
import numpy as np
import pandas as pd
import joblib

from src.ingestion.ecs_normalizer import ECSNormalizer
from src.features.feature_engineering import FeatureEngineeringPipeline
from src.models.supervised_detector import SupervisedThreatDetector
from src.models.anomaly_detector import UnsupervisedAnomalyDetector
from src.models.hybrid_ensemble import HybridThreatEnsemble
from src.correlation.correlation_engine import CrossLayerCorrelationEngine
from src.correlation.playbook_engine import ResponsePlaybookEngine
from src.explainability.explainer import CyberVisionExplainer
from src.cti.cti_client import ThreatIntelligenceClient


def run_benchmark():
    print("=" * 80)
    print("CYBERVISION RIGOROUS EMPIRICAL LATENCY & THROUGHPUT BENCHMARK")
    print("=" * 80)

    # 1. Load Data from DuckDB
    con = duckdb.connect("data/processed/cybervision_ecs.duckdb", read_only=True)
    df_raw = con.execute("SELECT * FROM ecs_events LIMIT 2000").df()
    con.close()
    print(f"[*] Loaded {len(df_raw)} records from DuckDB for benchmarking.")

    # 2. Setup Feature Pipeline
    pipeline = FeatureEngineeringPipeline()
    enriched_df, feat_names = pipeline.extract_features_from_df(df_raw)
    X = enriched_df[feat_names].values.astype(np.float32)
    pipeline.scaler.fit(X)
    X_scaled = pipeline.scaler.transform(X)

    # 3. Model Loading / Instantiation
    sup = SupervisedThreatDetector()
    sup.train_models(X_scaled[:1000], (enriched_df["ground_truth_label"].values[:1000] > 0).astype(int))
    
    anom = UnsupervisedAnomalyDetector()
    anom.train_models(X_scaled[:1000])

    hybrid = HybridThreatEnsemble(supervised_detector=sup, anomaly_detector=anom)

    # =========================================================================
    # TIMING BENCHMARKS
    # =========================================================================
    N_REPS = 500

    # 1. Model-Only Supervised Inference Latency
    t0 = time.perf_counter()
    for _ in range(N_REPS):
        _ = sup.predict_proba(X_scaled[:1], model_name="xgboost")
    lat_sup_model = ((time.perf_counter() - t0) / N_REPS) * 1000.0

    # 2. Model-Only Anomaly Scoring Latency
    t0 = time.perf_counter()
    for _ in range(N_REPS):
        _ = anom.score_anomaly(X_scaled[:1], model_name="iforest")
    lat_anom_model = ((time.perf_counter() - t0) / N_REPS) * 1000.0

    # 3. Model-Only Hybrid Ensemble Inference Latency
    t0 = time.perf_counter()
    for _ in range(N_REPS):
        _ = hybrid.predict_hybrid_score(X_scaled[:1])
    lat_hybrid_model = ((time.perf_counter() - t0) / N_REPS) * 1000.0

    # 4. Feature Extraction & Scaling Latency (Per Event)
    sample_row = df_raw.iloc[0:1]
    t0 = time.perf_counter()
    for _ in range(N_REPS):
        _df, _ = pipeline.extract_features_from_df(sample_row)
        for c in feat_names:
            if c not in _df.columns:
                _df[c] = 0.0
        _ = pipeline.scaler.transform(_df[feat_names].values)
    lat_feature_prep = ((time.perf_counter() - t0) / N_REPS) * 1000.0

    # 5. Full Detection Pipeline Latency (Per Event: Feature Prep + Hybrid Inference)
    lat_full_detect = lat_feature_prep + lat_hybrid_model

    # 6. TreeSHAP Attribution Latency (Model Only)
    explainer = CyberVisionExplainer(
        model=sup.models["xgboost"],
        feature_names=feat_names,
        background_data=X_scaled[:100]
    )
    t0 = time.perf_counter()
    N_XAI = 50
    for _ in range(N_XAI):
        _ = explainer.explain_instance_treeshap(X_scaled[0])
    lat_treeshap = ((time.perf_counter() - t0) / N_XAI) * 1000.0

    # 7. LIME Tabular Attribution Latency
    t0 = time.perf_counter()
    N_LIME = 10
    for _ in range(N_LIME):
        _ = explainer.explain_instance_lime(X_scaled[0])
    lat_lime = ((time.perf_counter() - t0) / N_LIME) * 1000.0

    # 8. Temporal Graph Correlation Latency (100 alerts)
    corr_engine = CrossLayerCorrelationEngine(time_window_minutes=30)
    alerts_sample = [
        {
            "event_id": f"EV-{i}",
            "timestamp": pd.Timestamp.now().isoformat(),
            "layer_source": "network" if i % 3 == 0 else ("host" if i % 3 == 1 else "application"),
            "src_ip": f"192.168.1.{i % 5}",
            "dst_ip": "10.0.0.1",
            "host_id": f"srv-app-0{i % 2}",
            "user_id": f"user_admin_{i % 3}",
            "hybrid_confidence": 0.85,
            "attack_category": "PortScan" if i % 2 == 0 else "PrivEsc",
            "mitre_technique_id": "T1046"
        }
        for i in range(100)
    ]
    t0 = time.perf_counter()
    N_CORR = 20
    for _ in range(N_CORR):
        _ = corr_engine.correlate_alerts(alerts_sample)
    lat_corr_graph = ((time.perf_counter() - t0) / N_CORR) * 1000.0

    # 9. SQLite CTI Cache Lookup Latency
    cti_client = ThreatIntelligenceClient(cache_db_path="data/cache/cti_cache.sqlite")
    t0 = time.perf_counter()
    N_CTI = 100
    for _ in range(N_CTI):
        _ = cti_client.check_ip_reputation("192.168.1.100")
    lat_cti_lookup = ((time.perf_counter() - t0) / N_CTI) * 1000.0

    # 10. Playbook Engine Selection Latency
    t0 = time.perf_counter()
    N_PB = 200
    for _ in range(N_PB):
        _ = ResponsePlaybookEngine.get_playbook_for_alert("T1046", "PortScan")
    lat_playbook = ((time.perf_counter() - t0) / N_PB) * 1000.0

    # 11. Full End-to-End Triage Latency (Detection + Correlation + CTI + TreeSHAP + Playbook)
    lat_e2e_triage = lat_full_detect + (lat_corr_graph / 100.0) + lat_cti_lookup + lat_treeshap + lat_playbook

    # 12. Batch Ingestion & Throughput (Events/sec)
    batch_X = X_scaled[:1000]
    t0 = time.perf_counter()
    for _ in range(10):
        _ = hybrid.predict_hybrid_score(batch_X)
    dur_batch = time.perf_counter() - t0
    throughput_eps = (1000 * 10) / dur_batch

    print("\n" + "=" * 80)
    print("EMPIRICAL TIMING RESULTS (MEASURED ON CURRENT HARDWARE):")
    print("=" * 80)
    print(f"1. Model-Only Supervised Latency (XGBoost):         {lat_sup_model:.3f} ms / event")
    print(f"2. Model-Only Anomaly Latency (Isolation Forest):   {lat_anom_model:.3f} ms / event")
    print(f"3. Model-Only Hybrid Ensemble Latency:              {lat_hybrid_model:.3f} ms / event")
    print(f"4. Feature Extraction & Scaling Latency:            {lat_feature_prep:.3f} ms / event")
    print(f"5. Full Detection Pipeline Latency (Prep + Model):  {lat_full_detect:.3f} ms / event")
    print(f"6. TreeSHAP Attribution Latency (Model Only):       {lat_treeshap:.3f} ms / alert")
    print(f"7. LIME Tabular Attribution Latency (Model Only):   {lat_lime:.3f} ms / alert")
    print(f"8. NetworkX Graph Correlation Latency (100 alerts): {lat_corr_graph:.3f} ms / batch")
    print(f"9. SQLite CTI Cache Lookup Latency:                 {lat_cti_lookup:.3f} ms / lookup")
    print(f"10. Playbook Selection Latency:                     {lat_playbook:.3f} ms / alert")
    print(f"11. Full End-to-End Triage Latency (Single Alert):  {lat_e2e_triage:.3f} ms / alert")
    print(f"12. Model Throughput (Batch Size 1,000):            {throughput_eps:,.1f} Events / sec")
    print("=" * 80)

    # Save to CSV for reproducible verification
    results_df = pd.DataFrame([
        {"Metric": "Model-Only Supervised (XGBoost) Latency", "Value_ms": round(lat_sup_model, 3), "Unit": "ms/event"},
        {"Metric": "Model-Only Anomaly (Isolation Forest) Latency", "Value_ms": round(lat_anom_model, 3), "Unit": "ms/event"},
        {"Metric": "Model-Only Hybrid Ensemble Latency", "Value_ms": round(lat_hybrid_model, 3), "Unit": "ms/event"},
        {"Metric": "Feature Extraction & Scaling Latency", "Value_ms": round(lat_feature_prep, 3), "Unit": "ms/event"},
        {"Metric": "Full Detection Pipeline Latency", "Value_ms": round(lat_full_detect, 3), "Unit": "ms/event"},
        {"Metric": "TreeSHAP Attribution Latency", "Value_ms": round(lat_treeshap, 3), "Unit": "ms/alert"},
        {"Metric": "LIME Tabular Attribution Latency", "Value_ms": round(lat_lime, 3), "Unit": "ms/alert"},
        {"Metric": "Graph Correlation Latency (100 alerts)", "Value_ms": round(lat_corr_graph, 3), "Unit": "ms/batch"},
        {"Metric": "SQLite CTI Cache Lookup Latency", "Value_ms": round(lat_cti_lookup, 3), "Unit": "ms/lookup"},
        {"Metric": "Playbook Selection Latency", "Value_ms": round(lat_playbook, 3), "Unit": "ms/alert"},
        {"Metric": "Full End-to-End Triage Latency", "Value_ms": round(lat_e2e_triage, 3), "Unit": "ms/alert"},
        {"Metric": "Model Batch Throughput", "Value_ms": round(throughput_eps, 1), "Unit": "Events/sec"}
    ])
    os.makedirs("results", exist_ok=True)
    results_df.to_csv("results/measured_empirical_latencies.csv", index=False)
    print("[+] Saved empirical latency benchmark to results/measured_empirical_latencies.csv")


if __name__ == "__main__":
    run_benchmark()
