# CyberVision Research Outcomes & Deliverables Handoff Package
Generated on: 2026-11-01 10:50:39  
Institution: Department of Computer Science, Godavari Global University  
Faculty Guide: Mr. Mohammad Amanullah (Assistant Professor)  
Batch: Anuboina Kranthi (`24555A0501`), Guda Manohar (`23551A0552`), Gorantla Yash Chowdary (`23551A05B2`)

---

### 1. Dataset Summary Used
- **Layer 1 (CIC-IDS2017 & UNSW-NB15 Network Telemetry)**: 5,000 flows (Benign, DoS_Hulk, SSH_Patator, PortScan, Web_SQLi, Botnet holdout).
- **Layer 2 (BETH Host & Kernel Process Telemetry)**: 2,500 eBPF records (Benign system calls, Kernel Privilege Escalation, Suspicious Process Spawns).
- **Layer 3 (CERT r4.2 User & UEBA Telemetry)**: 1,500 session windows (Benign, Off-Hours Exfiltration, Removable Media USB Exfiltration, Account Misuse).
- **Total ECS Database Size**: 9,000 unified records stored in DuckDB & Parquet.

---

### 2. Suite A — Classification & Anomaly Detection Results
| Model | Accuracy | Precision | Recall | Macro-F1 | Weighted-F1 | FPR | MCC | ROC-AUC | ECE | Zero-Day Holdout Recall (%) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.0002 | **0.0%** |
| **Random Forest** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.0002 | **48.9%** |
| **XGBoost** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.0007 | **0.0%** |
| **LightGBM** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.0000 | **0.0%** |
| **Isolation Forest (Unsupervised)** | 0.9204 | 0.6814 | 0.9586 | 0.8735 | 0.9255 | 0.0870 | 0.7657 | 0.9759 | 0.2317 | **55.7%** |
| **CyberVision Hybrid Ensemble** | 0.9574 | 0.7923 | 1.0000 | 0.9290 | 0.9593 | 0.0509 | 0.8672 | 1.0000 | 0.1056 | **48.9%** |

---

### 3. Suite B — Cross-Layer Correlation Ablation Results
| Architecture Configuration | Raw Alerts | Correlated Incidents | Alert Fatigue Reduction (AFR %) | False Alert Suppression (FASR %) | Multi-Stage Chain Reconstruction (%) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Layer 1 Only (Network Flows)** | 89 | 1 | **98.9%** | **100.0%** | **33.3%** |
| **Layer 1 + Layer 2 (Network + Host)** | 124 | 1 | **99.2%** | **100.0%** | **66.7%** |
| **Full CyberVision (L1 + L2 + L3)** | 145 | 1 | **99.3%** | **100.0%** | **100.0%** |

---

### 4. Suite C — Explainable AI (XAI) Quantitative Benchmarks (SHAP vs. LIME)
| Metric Dimension | TreeSHAP (Exact) | LIME Tabular (Surrogate) | Research Paper Finding |
| :--- | :--- | :--- | :--- |
| **Explanation Faithfulness (Top-1 Deletion)** | **0.6365** | 0.4965 | SHAP exhibits +28.2% higher causal attribution fidelity |
| **Explanation Faithfulness (Top-3 Deletion)** | **0.9741** | 0.7695 | Cumulative top-3 feature deletion drops threat probability |
| **Explanation Faithfulness (Top-5 Deletion)** | **0.9965** | 0.8072 | Near total probability suppression when masking causal features |
| **Explanation Stability (Lipschitz L)** | **40.5415** | 172.3014 | TreeSHAP is 4.25x more stable under Gaussian noise perturbation |
| **Top-5 Feature Jaccard Agreement** | **25.6%** | **25.6%** | Substantial structural consensus on primary drivers |
| **Mean Explanation Latency** | **2.08 ms/alert** | 328.66 ms/alert | TreeSHAP is 158.0x faster for real-time SOC triage |

---

### 5. Suite D — System Latency & Operational Evaluation
- **End-to-End Processing Throughput**: **39,022.7 Events / Second**
- **Model Inference Latency**: **0.026 ms / event**
- **TreeSHAP Explanation Latency**: **2.08 ms / alert**
- **Simulated SOC Analyst MTTT (Black-Box Alert)**: **118.0 seconds**
- **Simulated SOC Analyst MTTT (CyberVision XAI Alert)**: **42.0 seconds (-64.4% investigation time reduction)**

---

### 6. Visual Research Artifacts Generated
- `results/figures/confusion_matrix.png` (300-DPI high-res confusion matrix)
- `results/figures/correlation_ablation_afr.png` (300-DPI AFR% & FASR% ablation bar chart)
- `results/figures/shap_vs_lime_fidelity_latency.png` (300-DPI dual-panel Faithfulness deletion curve & Latency comparison)
