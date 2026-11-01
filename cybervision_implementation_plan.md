# CyberVision: An Explainable AI-Based Platform for Multi-Layer Cyber Threat Detection
## Complete Final Year B.Tech Project Implementation Plan & Research Execution Blueprint

**Institution:** Department of Computer Science, Godavari Global University  
**Faculty Guide:** Mr. Mohammad Amanullah (Assistant Professor)  
**Student Batch Details:**  
- **ANUBOINA KRANTHI** (Roll / Register No: `24555A0501`)  
- **GUDA MANOHAR** (Roll / Register No: `23551A0552`)  
- **GORANTLA YASH CHOWDARY** (Roll / Register No: `23551A05B2`)  

---

## 1. Executive Project Definition & Architectural Vision

### 1.1 What the Project Is (Formal Definition)
**CyberVision** is an end-to-end, multi-layer Security Operations Center (SOC) analytics platform and empirical cybersecurity research framework. Traditional Intrusion Detection Systems (IDS) and Security Information and Event Management (SIEM) platforms rely on static signature rules that fail against zero-day attacks, evaluate single telemetry layers in isolation (e.g., only network packets or only OS logs), and operate as "black-box" classifiers that flood SOC analysts with uncontextualized false alarms.

CyberVision solves these three limitations through a **5-Stage Unified Pipeline**:
1. **Multi-Layer Telemetry Normalization Engine**: Ingests heterogeneous security logs across three distinct operational layers—**Layer 1 (Network Flow Telemetry)**, **Layer 2 (Host & Kernel Process Telemetry)**, and **Layer 3 (User & Application Behavioral Telemetry)**—and maps them into a unified JSON/tabular format aligned with the [Elastic Common Schema (ECS)](https://www.elastic.co/docs/reference/ecs).
2. **Hybrid Multi-Model Threat Detection Engine**: Combines supervised gradient-boosted decision trees ([XGBoost](https://pypi.org/project/xgboost/), [LightGBM](https://pypi.org/project/lightgbm/), [Random Forest](https://pypi.org/project/scikit-learn/)) for high-precision classification of known attack categories with unsupervised behavioral anomaly detectors ([Isolation Forest](https://pypi.org/project/scikit-learn/), [Extended Isolation Forest / ECOD / COPOD](https://pypi.org/project/pyod/), and [PyTorch](https://pypi.org/project/torch/) Deep Autoencoders) to catch novel or zero-day behavioral deviations.
3. **Cross-Layer Graph Correlation & Alert Fusion Engine**: Constructs a temporal entity-relationship graph using [NetworkX](https://pypi.org/project/networkx/) linking IP addresses, hostnames, user accounts, and system processes across time windows. By correlating alerts across multiple layers and enriching them with external threat intelligence and [MITRE ATT&CK](https://attack.mitre.org/) tactics, CyberVision suppresses isolated single-layer false positives and elevates multi-stage attack chains.
4. **Explainable AI (XAI) Attribution & Narrative Layer**: Wraps every detection decision with game-theoretic local and global feature attributions using [SHAP (SHapley Additive exPlanations)](https://pypi.org/project/shap/) (`TreeExplainer` and `KernelExplainer`) and local surrogate approximations using [LIME](https://pypi.org/project/lime/). Every alert outputs a calibrated confidence score, a composite severity rating (`Low`, `Medium`, `High`, `Critical`), top-k contributing feature explanations, and a human-readable analyst narrative.
5. **Interactive SOC Analyst Dashboard & REST API**: Exposes real-time inference, correlation graphs, and XAI waterfall visualizations via a [FastAPI](https://pypi.org/project/fastapi/) backend and a multi-page [Streamlit](https://pypi.org/project/streamlit/) SOC Workbench.

### 1.2 Core Novelty & Research Contributions (For Conference Publication)
When defending this project during B.Tech reviews and submitting the final research paper to IEEE, Springer, or ACM conferences, emphasize four distinct research contributions:
- **Multi-Layer Cross-Domain Fusion vs. Siloed Detection**: Demonstrating mathematically and empirically that correlating Network (L1), Host/Kernel (L2), and User/Application (L3) telemetry reduces False Positive Rates (FPR) and Alert Fatigue Ratios (AFR) compared to standalone single-layer detectors.
- **Hybrid Supervised + Unsupervised Ensemble**: Benchmarking a weighted probability fusion of supervised gradient boosting and unsupervised reconstruction/isolation scoring to maintain high recall on both known signatures and unseen zero-day splits.
- **Quantitative XAI Evaluation in Cybersecurity**: Moving beyond visual plots to mathematically benchmark explanation **Faithfulness** (deletion/insertion curves), **Stability** (local Lipschitz continuity under perturbation), and **Computational Latency** (`ms/alert`) comparing [SHAP](https://pypi.org/project/shap/) and [LIME](https://pypi.org/project/lime/).
- **Actionable SOC Triage Compression**: Translating sub-symbolic feature attributions into [MITRE ATT&CK](https://attack.mitre.org/) technique mappings and measuring simulated analyst investigation time reduction.

---

## 2. Multi-Layer Benchmark Datasets to Gather

To validate that CyberVision operates across network devices, host endpoints, and application/user layers, gather the following four open-access benchmark datasets. You do **not** need to load 50+ GB of raw packet captures into memory at once; use the curated, stratified subset strategy described in the table below so the entire pipeline trains and evaluates cleanly on a standard laptop (8–16 GB RAM) or Google Colab.

| Layer & Role | Dataset Name | Official Source & Download Links | Threat Scenarios Covered | Recommended Project Subset Size |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 1: Network Traffic & Intrusion Flows** | **CIC-IDS2017** (Canadian Institute for Cybersecurity) | [UNB Official Portal](https://www.unb.ca/cic/datasets/ids-2017.html) / [Kaggle Cleaned CSV Mirror](https://www.kaggle.com/datasets/raihansultan/cicids2017) / [HuggingFace Temporal Split](https://huggingface.co/datasets/lacg030175/CICIDS2017) | Benign traffic, DoS (Hulk, GoldenEye, Slowloris), DDoS (LOIT), Brute Force (FTP-Patator, SSH-Patator), Web Attacks (SQLi, XSS), Botnet (ARES), PortScan, Infiltration | **250,000 stratified flows** (79 numeric flow features + attack category label; ~180 MB in Parquet) |
| **Layer 1B: Modern Network Intrusion Benchmark** | **UNSW-NB15** (UNSW Canberra Cyber Range Lab) | [UNSW Official Portal](https://research.unsw.edu.au/projects/unsw-nb15-dataset) / [Kaggle CSV Mirror](https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15) / [CIC Augmented UNSW-NB15](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html) | Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms (49 flow & packet features) | **257,673 official train/test split rows** (`UNSW_NB15_training-set.csv` & `testing-set.csv`; ~65 MB) |
| **Layer 2: Host & Kernel Process Telemetry** | **BETH Dataset** (BPF-Extended Tracking Honeypot) | [Kaggle Official Repository](https://www.kaggle.com/datasets/katehighnam/beth-dataset) / [CAMLIS Paper PDF](https://ceur-ws.org/Vol-3095/paper1.pdf) / [Official GitHub Benchmarks](https://github.com/jinxmirror13/BETH_Dataset_Analysis) | Cloud honeypot Linux kernel `ebpf` process calls (`processId`, `parentProcessId`, `userId`, `mountNamespace`, `eventId`, `argsNum`, `returnValue`) + DNS logs (`sus` & `evil` labels) | **500,000 process & DNS events** from the official train/val/test split (~110 MB) |
| **Layer 3: Application, Logon & User Behavior (UEBA)** | **CERT Insider Threat Dataset (r4.2)** (CMU SEI) or **LANL Cyber1** | [HuggingFace CERT r4.2 Mirror](https://huggingface.co/datasets/nguynn/cert-insider-threat-datasets) / [Kaggle CERT r4.2](https://www.kaggle.com/datasets/andrihjonior/cert-insider-threat-dataset-r4-2) / [LANL Multi-Source Cyber Events](https://csr.lanl.gov/data/cyber1/) | Multi-source application & user activity: `logon.csv` (after-hours logons), `device.csv` (USB thumb drives), `http.csv`, `email.csv`, `file.csv` (data exfiltration & privilege misuse) | **150,000 aggregated user-session windows** across `logon`, `device`, and `file` logs (~85 MB) |

---

## 3. Complete Technology Stack & Python Packages

Install all packages inside an isolated Python `3.10+` or `3.11+` virtual environment (`venv` or `conda`). Every package listed below is 100% open-source and pre-verified on PyPI.

| Subsystem Layer | Package Name | PyPI / Official Link | Minimum Version | Exact Purpose in CyberVision |
| :--- | :--- | :--- | :--- | :--- |
| **Data Ingestion & Common Schema** | `pandas` | [PyPI: pandas](https://pypi.org/project/pandas/) | `>=2.2.0` | High-speed tabular log parsing, timestamp alignment, and feature windowing |
| **Data Ingestion & Common Schema** | `numpy` | [PyPI: numpy](https://pypi.org/project/numpy/) | `>=1.26.0` | Vectorized array operations, log-scaling, and numerical stability handling |
| **Data Ingestion & Common Schema** | `duckdb` | [PyPI: duckdb](https://pypi.org/project/duckdb/) | `>=1.0.0` | Embedded analytical SQL database for fast querying over millions of normalized ECS logs |
| **Data Ingestion & Common Schema** | `pydantic` | [PyPI: pydantic](https://pypi.org/project/pydantic/) | `>=2.7.0` | Enforcing strict schema validation for the Unified Log Format (ECS JSON schema) |
| **Supervised Threat Classification** | `scikit-learn` | [PyPI: scikit-learn](https://pypi.org/project/scikit-learn/) | `>=1.5.0` | Random Forest, Extra Trees, Stratified K-Fold, `RobustScaler`, and evaluation metrics |
| **Supervised Threat Classification** | `xgboost` | [PyPI: xgboost](https://pypi.org/project/xgboost/) | `>=2.1.0` | Primary high-speed gradient boosted decision trees for multi-class attack detection |
| **Supervised Threat Classification** | `lightgbm` | [PyPI: lightgbm](https://pypi.org/project/lightgbm/) | `>=4.5.0` | Fast histogram-based gradient boosting for massive network flow and host datasets |
| **Supervised Threat Classification** | `imbalanced-learn` | [PyPI: imbalanced-learn](https://pypi.org/project/imbalanced-learn/) | `>=0.12.0` | `SMOTE`, `ADASYN`, and `RandomUnderSampler` to handle rare attack classes (e.g., SQLi, Worms) |
| **Unsupervised Anomaly Detection** | `pyod` | [PyPI: pyod](https://pypi.org/project/pyod/) | `>=2.0.0` | Scalable outlier detection (`IForest`, `ECOD`, `COPOD`, `LOF`) for zero-day behavior scoring |
| **Unsupervised Anomaly Detection** | `torch` | [PyPI: torch](https://pypi.org/project/torch/) | `>=2.3.0` | Deep Reconstruction Autoencoder (`MLP` / `LSTM` Autoencoder) for sequence anomaly scoring |
| **Explainable AI (XAI) Engine** | `shap` | [PyPI: shap](https://pypi.org/project/shap/) | `>=0.45.0` | Game-theoretic `TreeExplainer` and `KernelExplainer` for exact feature attribution & plots |
| **Explainable AI (XAI) Engine** | `lime` | [PyPI: lime](https://pypi.org/project/lime/) | `>=0.2.0.1` | `LimeTabularExplainer` for local linear surrogate explanations and comparative XAI benchmarking |
| **Correlation & CTI Mapping** | `networkx` | [PyPI: networkx](https://pypi.org/project/networkx/) | `>=3.3` | Multi-layer entity correlation graph (`IP <-> Host <-> User <-> Process`) & attack path scoring |
| **Correlation & CTI Mapping** | `mitreattack-python` | [PyPI: mitreattack-python](https://pypi.org/project/mitreattack-python/1.5.1/) | `>=1.5.1` | Mapping classified threats and host events to official [MITRE ATT&CK](https://attack.mitre.org/) Tactics & Techniques |
| **Experiment & Tuning** | `optuna` | [PyPI: optuna](https://pypi.org/project/optuna/) | `>=4.0.0` | Automated Bayesian hyperparameter optimization for XGBoost, LightGBM, and Autoencoders |
| **Experiment & Tuning** | `mlflow` | [PyPI: mlflow](https://pypi.org/project/mlflow/) | `>=2.15.0` | Tracking all training runs, hyperparameters, confusion matrices, and XAI latency benchmarks |
| **Backend API & SOC UI** | `fastapi` | [PyPI: fastapi](https://pypi.org/project/fastapi/) | `>=0.115.0` | RESTful inference API (`/ingest`, `/detect`, `/correlate`, `/explain`) |
| **Backend API & SOC UI** | `uvicorn` | [PyPI: uvicorn](https://pypi.org/project/uvicorn/) | `>=0.30.0` | Lightning-fast ASGI web server hosting the FastAPI threat detection engine |
| **Backend API & SOC UI** | `streamlit` | [PyPI: streamlit](https://pypi.org/project/streamlit/) | `>=1.38.0` | Interactive multi-page SOC Analyst Dashboard for real-time alert triage and XAI inspection |
| **Visualization & Reporting** | `plotly` | [PyPI: plotly](https://pypi.org/project/plotly/) | `>=5.24.0` | Interactive correlation graphs, ROC/PR curves, and real-time SOC telemetry charts |
| **Visualization & Reporting** | `seaborn` | [PyPI: seaborn](https://pypi.org/project/seaborn/) | `>=0.13.2` | Publication-grade confusion matrices, feature distributions, and ablation plots for the paper |

---

## 4. External API Keys & Threat Intelligence Integrations

To enrich detected network and host alerts with real-world Cyber Threat Intelligence (CTI) and automate analyst explanations without paying for commercial licenses, register for the following **100% Free-Tier API keys** and store them in a local `.env` file (never commit `.env` to Git):

| API Service | Official Portal & Docs | Free Tier Quota | Role in CyberVision Pipeline | Offline / Local Fallback Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **AlienVault OTX (Open Threat Exchange)** | [AlienVault OTX Portal](https://otx.alienvault.com/) | **Unlimited / Free Community Access** (up to 3,500+ queries/hr) | Queries community threat "Pulses" for suspicious IPs, domains, file hashes, and associated malware families | Local SQLite/DuckDB cache of top 10,000 known malicious OTX indicators |
| **AbuseIPDB API v2** | [AbuseIPDB API Docs](https://docs.abuseipdb.com/) / [Pricing](https://www.abuseipdb.com/pricing) | **1,000 IP checks/day** (Free Forever Individual Plan) | Retrieves community abuse confidence score (`0–100%`), ISP, country, and abuse categories for external attacker IPs | Pre-cached JSON lookup table for all attacker IPs present in CIC-IDS2017 & UNSW-NB15 |
| **VirusTotal Public API v3** | [VirusTotal Pricing & Free Tier](https://domscan.net/pricing/virustotal) | **500 requests/day** & **4 requests/minute** (Noncommercial Free Tier) | Checks suspicious process hashes, domains, or external IPs flagged by `High`/`Critical` alerts across 70+ antivirus engines | Rate-limited LRU cache (`@lru_cache` + SQLite) triggered only on `Critical` severity incidents |
| **GreyNoise Community API v3** | [GreyNoise Community API Docs](https://docs.greynoise.io/docs/using-the-greynoise-community-api) | **Free Community Tier** (`api.greynoise.io/v3/community/ip/{ip}`) | Distinguishes targeted attacks from benign internet background scanners (e.g., Shodan, Censys) to further suppress false alerts | Default heuristic tagger based on port scan fan-out ratio when offline |
| **Shodan Developer API** | [Shodan Developer Portal](https://developer.shodan.io/) | **Free Account Tier** (100 query credits/month + free host lookups) | Inspects open ports and exposed services on external hosts communicating with internal enterprise assets | Optional enrichment module; gracefully skipped if quota is reached |
| **LLM Narrative API (Optional: Gemini API / Local Ollama)** | [Google AI Studio](https://aistudio.google.com/) | **Free Tier API** (or 100% offline local LLM via Ollama) | Converts structured SHAP top-5 feature values + MITRE ATT&CK tags into a concise 3-sentence natural language SOC triage summary | Deterministic rule-based template generator (`f"Alert triggered by {top_feature_1} ({shap_val_1:+.2f})..."`) |

---

## 5. Step-by-Step Implementation Plan (8 Execution Phases)

Execute the project systematically across these **8 sequential phases** (designed for a 12-to-16-week B.Tech capstone schedule or intensive sprint execution in your IDE/workspace).

### Phase 1: Repository Scaffolding, Environment & Schema Setup (Week 1)
1. **Create Standardized Directory Structure**:
   ```text
   cybervision/
   ├── config/                  # config.yaml, ecs_schema.json, mitre_mapping.json
   ├── data/
   │   ├── raw/                 # Downloaded CIC-IDS2017, UNSW-NB15, BETH, CERT r4.2 files
   │   ├── processed/           # Cleaned Parquet files & Unified ECS DuckDB database
   │   └── cache/               # Offline CTI API response cache (cti_cache.sqlite)
   ├── src/
   │   ├── ingestion/           # Multi-layer log parsers & ECS normalizer (Pydantic + DuckDB)
   │   ├── features/            # Sliding window feature engineering & RobustScaler pipelines
   │   ├── models/              # Supervised (XGBoost, LightGBM, RF) & Unsupervised (PyOD, Autoencoder)
   │   ├── correlation/         # NetworkX multi-layer entity graph & composite risk scorer
   │   ├── explainability/      # SHAP TreeExplainer, LIME wrapper, & narrative generator
   │   ├── cti/                 # AbuseIPDB, OTX, VirusTotal, GreyNoise async clients with caching
   │   └── evaluation/          # Benchmark calculator (Classification, Correlation, XAI Faithfulness)
   ├── api/                     # FastAPI backend (main.py, schemas.py, routers/)
   ├── dashboard/               # Streamlit multi-page SOC Analyst UI (app.py, pages/)
   ├── notebooks/               # Reproducible Jupyter notebooks for EDA & paper plots
   ├── results/                 # Exported CSV benchmark tables, JSON logs, and 300-DPI PDF/PNG plots
   ├── requirements.txt         # Locked Python dependencies
   └── .env.example             # Template for API keys
   ```
2. **Initialize Virtual Environment & Tracking**: Set up `python -m venv .venv`, install all packages from Section 3, and initialize a local [MLflow](https://pypi.org/project/mlflow/) tracking directory (`mlruns/`) so every experiment is automatically logged.

### Phase 2: Multi-Source Data Acquisition & Unified Log Normalization (Weeks 2–3)
1. **Clean Raw Datasets**:
   - In [CIC-IDS2017](https://www.kaggle.com/datasets/raihansultan/cicids2017) and [UNSW-NB15](https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15), replace `Inf` and `-Inf` values in `Flow Bytes/s` and `Flow Packets/s` with `NaN`, drop corrupted rows, remove duplicate records, and standardize column names to `snake_case`.
   - In [BETH](https://www.kaggle.com/datasets/katehighnam/beth-dataset), parse kernel process telemetry (`processId`, `parentProcessId`, `userId`, `mountNamespace`, `eventId`, `argsNum`, `returnValue`) and map `evil` (`0` vs `1`) and `sus` (`0` vs `1`) flags.
   - In [CERT r4.2](https://huggingface.co/datasets/nguynn/cert-insider-threat-datasets), extract user session aggregates across `logon.csv`, `device.csv`, and `file.csv` grouped by `(user_id, host_id, 1_hour_window)`.
2. **Implement the Unified Common Schema ([Elastic Common Schema - ECS](https://www.elastic.co/docs/reference/ecs))**:
   - Build `src/ingestion/ecs_normalizer.py` using [Pydantic](https://pypi.org/project/pydantic/) to transform every log from Layers 1, 2, and 3 into a canonical record containing:
     - `event_id` (UUID), `timestamp` (ISO-8601 UTC), `layer_source` (`network` | `host` | `application`)
     - `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
     - `host_id`, `user_id`, `process_name`, `process_id`, `parent_process_id`
     - `event_action`, `raw_features` (JSON/Vector), `ground_truth_label`, `attack_category`, `mitre_technique_id`
   - Store normalized tables in [DuckDB](https://pypi.org/project/duckdb/) (`data/processed/cybervision_ecs.duckdb`) and `.parquet` files for sub-second loading.

### Phase 3: Multi-Layer Feature Engineering & Temporal Windowing (Week 4)
1. **Layer-Specific & Cross-Layer Temporal Features**:
   - Compute rolling 1-minute and 5-minute behavioral aggregations per `src_ip`, `host_id`, and `user_id`: connection fan-out degree, unique destination ports contacted, failed logon burst rate, child-process spawn velocity, and off-hours activity indicator (`is_off_hours`).
2. **Leakage-Free Preprocessing Pipeline**:
   - Split datasets using **strict temporal splits** (e.g., Monday–Thursday vs. Friday in [CIC-IDS2017](https://huggingface.co/datasets/lacg030175/CICIDS2017)) and **stratified 80/10/10 train/validation/test splits** (fixing `random_state=42`).
   - Fit `RobustScaler` (from [scikit-learn](https://pypi.org/project/scikit-learn/)) and `SMOTE` (from [imbalanced-learn](https://pypi.org/project/imbalanced-learn/)) **strictly on the training split**—never on validation or test data—to prevent data leakage.

### Phase 4: Multi-Layer ML & Behavioral Anomaly Detection Engine (Weeks 5–7)
1. **Supervised Known-Threat Classifiers**:
   - Train baseline and ensemble models across each layer: `LogisticRegression` (baseline), `RandomForestClassifier`, `XGBClassifier` ([XGBoost](https://pypi.org/project/xgboost/)), and `LGBMClassifier` ([LightGBM](https://pypi.org/project/lightgbm/)).
   - Use [Optuna](https://pypi.org/project/optuna/) (50 trials per model) to optimize `max_depth`, `learning_rate`, `subsample`, `colsample_bytree`, and `scale_pos_weight` maximizing **Macro F1-Score**.
   - Apply `CalibratedClassifierCV` (Platt scaling / isotonic regression) so predicted probabilities $P_{\text{sup}}(y|x) \in [0, 1]$ represent true empirical confidence scores.
2. **Unsupervised Zero-Day & Behavioral Anomaly Detectors**:
   - Train [PyOD](https://pypi.org/project/pyod/) models (`IForest`, `ECOD`, `COPOD`) and a [PyTorch](https://pypi.org/project/torch/) Deep Reconstruction Autoencoder (`Input -> 64 -> 32 -> 16 -> 32 -> 64 -> Output` with MSE reconstruction loss) **exclusively on benign training traffic**.
   - Normalize raw anomaly reconstruction/isolation scores into a calibrated anomaly probability $S_{\text{anom}}(x) \in [0, 1]$ using empirical quantile transformation.
3. **Hybrid Ensemble Threat Score**:
   - Compute the unified layer detection probability combining supervised certainty and unsupervised novelty detection:
     $$P_{\text{hybrid}}(x) = \alpha \cdot P_{\text{sup}}(x) + (1 - \alpha) \cdot S_{\text{anom}}(x)$$
     where $\alpha \in [0, 1]$ (default $\alpha = 0.65$, tuned on the validation set) balances signature precision with zero-day sensitivity.

### Phase 5: Cross-Layer Event Correlation & Alert Fusion Engine (Weeks 8–9)
1. **Controlled Multi-Layer Attack Campaign Simulation**:
   - Because public datasets are collected in separate labs, build a deterministic **Entity Alignment & Scenario Stitcher** (`src/correlation/scenario_builder.py`) that maps shared enterprise entity IDs (`Host_A = 192.168.10.50`, `User_12`, `Attacker_IP = 205.174.165.73`) across synchronized 5-minute time windows:
     - *Stage 1 (Layer 1 - Network)*: External Brute Force / Web Exploit from `CIC-IDS2017` targeting `Host_A`.
     - *Stage 2 (Layer 2 - Host/Kernel)*: Suspicious privilege escalation / anomalous child process spawn (`BETH` kernel event) on `Host_A`.
     - *Stage 3 (Layer 3 - Application/UEBA)*: Abnormal off-hours file access or USB exfiltration (`CERT r4.2`) by `User_12` on `Host_A`.
2. **Temporal Entity Correlation Graph ([NetworkX](https://pypi.org/project/networkx/))**:
   - Construct a directed temporal graph $G = (V, E)$ within sliding time windows $\Delta t = 5\text{ min}$, where nodes $V$ represent `{IP, Host, User, Process}` and edges $E$ carry triggered layer alerts and timestamps.
3. **Composite Severity & Confidence Formula**:
   - Calculate the correlated incident risk score $R_{\text{incident}} \in [0, 100]$ for every connected subgraph:
     $$R_{\text{incident}} = 100 \times \text{clip}\left( w_1 \max_{i} P_{\text{hybrid}}(e_i) + w_2 \frac{L_{\text{active}}}{3} + w_3 C_{\text{MITRE}} + w_4 I_{\text{CTI}}, \; 0, \; 1 \right)$$
     where:
     - $\max_{i} P_{\text{hybrid}}(e_i)$ is the peak hybrid model confidence across correlated events ($w_1 = 0.45$),
     - $L_{\text{active}} \in \{1, 2, 3\}$ is the number of distinct telemetry layers corroborating the entity ($w_2 = 0.25$),
     - $C_{\text{MITRE}} \in [0, 1]$ is the kill-chain progression score across [MITRE ATT&CK](https://attack.mitre.org/) tactics (`Initial Access -> Execution -> Privilege Escalation -> Exfiltration`, $w_3 = 0.15$),
     - $I_{\text{CTI}} \in [0, 1]$ is the normalized external threat intelligence reputation score from [AbuseIPDB](https://www.abuseipdb.com/) / [AlienVault OTX](https://otx.alienvault.com/) ($w_4 = 0.15$).
   - Assign discrete **Severity Levels**:
     - `0–39`: **Low** (Log only / Suppressed single-layer noise)
     - `40–69`: **Medium** (Single-layer high-confidence or two-layer low-confidence alert)
     - `70–89`: **High** (Multi-layer corroborated threat)
     - `90–100`: **Critical** (Active multi-stage kill-chain with CTI confirmation)

### Phase 6: Explainable AI (XAI) Attribution & Narrative Layer (Weeks 10–11)
1. **Local & Global Feature Attribution**:
   - Integrate `shap.TreeExplainer` ([SHAP](https://pypi.org/project/shap/)) for sub-15ms exact Shapley value extraction on [XGBoost](https://pypi.org/project/xgboost/) / [LightGBM](https://pypi.org/project/lightgbm/) models, and `shap.KernelExplainer` / Integrated Gradients for the [PyTorch](https://pypi.org/project/torch/) Autoencoder reconstruction error.
   - Integrate `LimeTabularExplainer` ([LIME](https://pypi.org/project/lime/)) to generate local linear surrogate explanations for every flagged alert so you can benchmark **SHAP vs. LIME** directly in your research paper.
2. **Automated Analyst Explanation Card**:
   - For every alert, extract the top-5 positively contributing features $\{(f_k, \phi_k)\}_{k=1}^5$, compare each feature's observed value $x_{i,k}$ against the benign baseline 95th percentile, map the behavior to [MITRE ATT&CK](https://attack.mitre.org/), and generate a structured explanation card:
     > *"Alert CV-2026-08412 classified as **SSH-BruteForce / Privilege Escalation** (**Confidence**: 96.4%, **Severity**: Critical [Score: 92.8/100]). Primary AI triggers: (1) `destination_port = 22` (+0.34 SHAP), (2) `syn_ack_packet_rate = 1,420/s` [18.4x above benign baseline] (+0.29 SHAP), and (3) correlated `BETH` kernel `setuid(0)` process call on `Host-192.168.10.50` within 94 seconds. Mapped to MITRE ATT&CK `T1110` (Brute Force) & `T1548` (Abuse Elevation Control)."*

### Phase 7: SOC Analyst Workbench Dashboard & FastAPI Service (Weeks 12–13)
1. **Build the FastAPI Service (`api/main.py`)**:
   - Create 4 clean REST endpoints: `POST /api/v1/ingest` (normalizes raw logs to ECS), `POST /api/v1/detect` (returns layer predictions & anomaly scores), `GET /api/v1/incidents` (returns correlated multi-layer incidents sorted by severity), and `GET /api/v1/explain/{alert_id}` (returns SHAP/LIME values, MITRE mapping, and narrative).
2. **Build the 4-Page Streamlit SOC Dashboard (`dashboard/app.py`)**:
   - **Page 1: Executive SOC Overview**: Live KPI metric cards (Total Logs Ingested, Raw Alerts vs. Correlated Incidents, False Alert Reduction %, Mean Triage Latency), real-time severity breakdown, and MITRE ATT&CK tactic heatmap.
   - **Page 2: Multi-Layer Incident Correlation Explorer**: Interactive [Plotly](https://pypi.org/project/plotly/) / [NetworkX](https://pypi.org/project/networkx/) node-link graph showing how a network flow, a host process call, and a user logon connect into a single incident timeline.
   - **Page 3: Explainable AI (XAI) Deep-Dive Inspector**: Side-by-side **SHAP Waterfall Plot**, **LIME Feature Weight Bar Chart**, feature deviation table (Observed Value vs. Benign Normal Range), CTI enrichment badge, and natural-language explanation.
   - **Page 4: Research Benchmarks & Ablation Viewer**: Interactive viewer displaying confusion matrices, ROC/PR curves, and XAI faithfulness/latency tables directly from `results/`.

### Phase 8: Research Benchmarking, Ablation Studies & Artifact Export (Weeks 14–15)
1. **Automated Evaluation Suite (`src/evaluation/run_benchmarks.py`)**:
   - Execute all 4 experimental evaluation suites defined in Section 6 below and automatically export clean CSV tables and 300-DPI figures into `results/` for direct inclusion in your conference paper.

---

## 6. Calculable Research Metrics, Benchmarks & Experimental Design

To make your B.Tech project publishable at top IEEE/Springer/ACM conferences, your code must calculate and export **four rigorous quantitative benchmark suites**:

### 6.1 Suite A: Threat Detection & Classification Metrics (Per Layer & Hybrid Ensemble)
Evaluate across **Baseline Models** (Rule/Threshold heuristic, Logistic Regression, Standalone Decision Tree, Standalone Isolation Forest) vs. **CyberVision Hybrid Ensemble** (XGBoost + LightGBM + Autoencoder):
- **Precision, Recall (Detection Rate), and Macro/Weighted F1-Score**:
  $$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall (DR)} = \frac{TP}{TP + FN}, \quad F_1 = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
- **False Positive Rate (FPR) & False Negative Rate (FNR)**:
  $$\text{FPR} = \frac{FP}{FP + TN}, \quad \text{FNR} = \frac{FN}{TP + FN}$$
- **Matthews Correlation Coefficient (MCC)** *(Critical for highly imbalanced cybersecurity datasets)*:
  $$\text{MCC} = \frac{TP \cdot TN - FP \cdot FN}{\sqrt{(TP+FP)(TP+FN)(TN+FP)(TN+FN)}}$$
- **ROC-AUC and PR-AUC (Precision-Recall Area Under Curve)**: PR-AUC is mandatory when attack traffic represents $<5\%$ of total volume.
- **Expected Calibration Error (ECE)**: Measures how closely the system's confidence score matches true empirical accuracy across $M=10$ confidence bins:
  $$\text{ECE} = \sum_{m=1}^{M} \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$

### 6.2 Suite B: Multi-Layer Correlation & SOC Workload Reduction Metrics
Demonstrate the exact mathematical benefit of the Cross-Layer Correlation Engine through an **Ablation Study** (*Single-Layer Network Only* vs. *Network + Host* vs. *Full 3-Layer CyberVision*):
- **Alert Fatigue Reduction Ratio (AFR)**: Percentage reduction in raw alerts requiring human review after graph correlation and low-severity single-layer noise suppression:
  $$\text{AFR} = \left( 1 - \frac{N_{\text{correlated\_incidents}}}{N_{\text{raw\_alerts}}} \right) \times 100\%$$
- **Correlated False Alert Suppression Rate (FASR)**: Percentage of single-layer false positives ($FP_{\text{raw}}$) downgraded below the triage threshold ($\text{Severity} < 40$) by cross-layer verification:
  $$\text{FASR} = \frac{FP_{\text{raw}} - FP_{\text{correlated}}}{FP_{\text{raw}}} \times 100\%$$
- **Multi-Stage Attack Chain Reconstruction Completeness ($C_{\text{chain}}$)**: Fraction of ground-truth multi-step attack steps correctly linked into a single connected incident graph.

### 6.3 Suite C: Quantitative Explainable AI (XAI) Benchmarks (SHAP vs. LIME vs. Feature Importance)
Reviewers at cybersecurity AI conferences reject papers that only show pretty SHAP screenshots. Calculate these **four mathematical XAI metrics** across 500 sampled test alerts:
1. **Explanation Faithfulness (Deletion / Comprehensiveness Score)**: Mask/replace the top-$k$ ($k \in \{1, 3, 5\}$) highest-attributed features with their benign median baseline $\bar{x}_k$ and measure the drop in predicted threat probability:
   $$\text{Faithfulness}_k = \frac{1}{N} \sum_{i=1}^{N} \left( P_{\text{hybrid}}(x_i) - P_{\text{hybrid}}(x_i \setminus \text{Top-}k) \right)$$
   *(Higher drop proves the explanation accurately identified the true causal features driving the model's alert).*
2. **Explanation Stability (Local Lipschitz Continuity)**: Add small Gaussian noise $\epsilon \sim \mathcal{N}(0, 0.01\sigma)$ to an input alert $x_i \to x_i'$ and measure the relative variance in the explanation vector $\phi(x)$:
   $$L(x_i) = \max_{x_i' \in \mathcal{B}_\epsilon(x_i)} \frac{\|\phi(x_i) - \phi(x_i')\|_2}{\|x_i - x_i'\|_2}$$
   *(Lower $L(x_i)$ proves the explanation is stable and trustworthy—TreeSHAP consistently outperforms LIME here).*
3. **Top-$k$ Feature Agreement (Jaccard Similarity & Spearman Rank $\rho$)**: Measure structural agreement between SHAP and LIME top-5 feature sets:
   $$J(\text{SHAP}_k, \text{LIME}_k) = \frac{|\text{Top-}k(\text{SHAP}) \cap \text{Top-}k(\text{LIME})|}{|\text{Top-}k(\text{SHAP}) \cup \text{Top-}k(\text{LIME})|}$$
4. **Explanation Generation Latency ($\text{ms/alert}$)**: Mean and 95th-percentile wall-clock time required to compute an explanation per alert (`TreeSHAP` vs. `KernelSHAP` vs. `LIME`).

### 6.4 Suite D: Operational & Analyst Triage Efficiency Metrics
- **End-to-End Detection & Explanation Throughput**: Events processed per second (`EPS`) and mean end-to-end latency ($\tau_{\text{norm}} + \tau_{\text{infer}} + \tau_{\text{corr}} + \tau_{\text{XAI}}$ in milliseconds).
- **Analyst Investigation Complexity Reduction (Task Simulation / User Study)**: Conduct a controlled 15-alert triage test with 5–10 computer science peers comparing **Condition A (Raw Black-Box Alert: IP + Timestamp + "Anomaly Detected")** vs. **Condition B (CyberVision XAI Alert: Confidence + Severity + Top-3 SHAP Triggers + MITRE Mapping)**, recording **Mean Time to Triage (MTTT in seconds)** and **Triage Decision Accuracy (%)**.

---

## 7. What To Do vs. What NOT To Do (Critical Engineering Guardrails)

| Dimension | What You MUST Do (Best Practices) | What You Must NOT Do (Common B.Tech Pitfalls) |
| :--- | :--- | :--- |
| **Dataset Selection** | Use modern, multi-layer datasets ([CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset), [BETH](https://www.kaggle.com/datasets/katehighnam/beth-dataset), [CERT r4.2](https://huggingface.co/datasets/nguynn/cert-insider-threat-datasets)) covering Network, Host, and User layers. | **DO NOT** use outdated 1990s datasets like `KDD Cup 99` or `NSL-KDD`—conference reviewers automatically reject papers built on KDD99. |
| **Data Splitting & Scaling** | Perform temporal/stratified splitting **first**, and fit `RobustScaler` and `SMOTE` **only on the training set**. | **DO NOT** apply `SMOTE` or `StandardScaler` on the full CSV before `train_test_split`—that causes severe data leakage and fake 99.99% accuracy. |
| **Zero-Day Evaluation** | Hold out at least one entire attack family (e.g., `Heartbleed` or `Botnet`) from supervised training to prove the unsupervised anomaly module catches unseen threats. | **DO NOT** train supervised classifiers on all attack labels and claim the model detects "unseen/zero-day" attacks without an unseen holdout test. |
| **Explainable AI (XAI)** | Compute quantitative XAI metrics (**Faithfulness**, **Stability**, **Latency**, **Jaccard overlap**) and run XAI only on flagged alerts or stratified samples. | **DO NOT** run `KernelSHAP` or `LIME` synchronously on 2 million benign rows (it will freeze your laptop for days), and do not stop at static screenshots. |
| **Cross-Layer Correlation** | Align timestamps and entity IDs into a unified [Elastic Common Schema (ECS)](https://www.elastic.co/docs/reference/ecs) table and build a reproducible multi-layer attack scenario stitcher. | **DO NOT** build three disconnected Jupyter notebooks that never combine or correlate outputs across Network, Host, and Application layers. |
| **API Key Handling** | Cache all external Threat Intelligence lookups locally in SQLite/JSON and only query live APIs on deduplicated suspicious IPs. | **DO NOT** fire live API requests inside a `for` loop over 100,000 dataset rows—you will hit `HTTP 429 Too Many Requests` in 60 seconds. |

---

## 8. Final Project Deliverables Checklist & Conference Paper Handoff Protocol

### 8.1 Complete List of Final Project Deliverables
At the conclusion of executing this implementation plan, your team will possess **6 tangible project deliverables** ready for Review 0 through Final Viva and conference submission:
1. **Unified Multi-Layer ECS Dataset & Normalization Pipeline** (`data/processed/cybervision_ecs.duckdb` + Python ingestion scripts).
2. **Trained & Calibrated Multi-Layer Model Suite** (`models/saved/`: serialized `XGBoost`, `LightGBM`, `RandomForest`, `IsolationForest`, `ECOD`, and `PyTorch Autoencoder` weights + `CalibratedClassifierCV` wrappers).
3. **Cross-Layer Graph Correlation & XAI Attribution Engine** (`src/correlation/` & `src/explainability/`: NetworkX correlation module + SHAP/LIME attribution & narrative generator).
4. **Live CyberVision SOC Analyst Platform** (`api/` + `dashboard/`: working FastAPI backend and 4-page interactive Streamlit SOC Workbench).
5. **Reproducible Research Benchmark & Visual Artifact Bundle** (`results/`: CSV benchmark tables + 300-DPI ROC/PR curves, confusion matrices, ablation bar charts, and SHAP waterfall/beeswarm plots).
6. **Final Year Project Documentation & Conference Research Paper** (Review slide decks, B.Tech thesis report, and IEEE/Springer-formatted research manuscript).

### 8.2 Exact "Outcome Handoff Template" (For Your Next Step After Execution)
Once you execute this implementation plan (using your IDE / coding environment) and generate the outputs, copy and paste the following **Research Outcomes Handoff Package** back into our conversation. Using your exact numbers, I will write your complete, publication-ready **IEEE / Springer Conference Research Paper**:

```markdown
### CYBERVISION RESEARCH OUTCOMES HANDOFF TEMPLATE
1. Dataset Summary Used:
   - Layer 1 (CIC-IDS2017 / UNSW-NB15): [Total rows, Train/Val/Test split counts, Attack classes included]
   - Layer 2 (BETH Host/Kernel): [Total rows, Benign vs. Evil/Suspicious counts]
   - Layer 3 (CERT r4.2 / LANL UEBA): [Total user-session windows, Benign vs. Insider Threat counts]

2. Suite A — Classification & Anomaly Detection Results (Paste CSV or Table):
   - Per-model Accuracy, Precision, Recall, Macro-F1, Weighted-F1, FPR, MCC, ROC-AUC, PR-AUC, and ECE for:
     [Logistic Regression, Random Forest, XGBoost, LightGBM, Isolation Forest, Autoencoder, CyberVision Hybrid Ensemble]
   - Unseen / Zero-Day Holdout Attack Recall (%): [e.g., Recall on held-out Botnet/Infiltration class]

3. Suite B — Cross-Layer Correlation Ablation Results:
   - Raw Alerts Generated (Single-Layer): [Count & FPR]
   - Correlated Incidents After Multi-Layer Graph Fusion: [Count & FPR]
   - Alert Fatigue Reduction Ratio (AFR %): [Value]
   - Correlated False Alert Suppression Rate (FASR %): [Value]

4. Suite C — Explainable AI (XAI) Quantitative Benchmarks (SHAP vs. LIME):
   - Faithfulness Deletion Score (Top-1, Top-3, Top-5 probability drop): [SHAP values vs. LIME values]
   - Explanation Stability / Perturbation Variance (Lipschitz L): [SHAP vs. LIME]
   - Top-5 Feature Jaccard Agreement (%): [Value]
   - Mean Explanation Latency (ms/alert): [TreeSHAP ms vs. KernelSHAP ms vs. LIME ms]
   - Top-5 Most Influential Features per Layer: [List feature names & mean |SHAP| values]

5. Suite D — System Latency & Analyst Triage Evaluation:
   - End-to-End Pipeline Throughput (Events/sec) & Mean Alert Latency (ms): [Values]
   - Simulated Analyst Triage Study (if conducted): [Mean Time to Triage (s) Black-Box vs. CyberVision XAI]
   - Target Conference Format: [e.g., IEEE 2-Column Conference Template / Springer LNCS / Elsevier]
```
