"""
Ingestion Pipeline for Real Datasets (CIC-IDS2017 & UNSW-NB15).
Normalizes raw real network flows into the Unified Elastic Common Schema (ECS)
and registers them into DuckDB storage with `is_synthetic = 0`.
"""

import os
import json
import uuid
import datetime
import numpy as np
import pandas as pd
import duckdb

MITRE_MAPPING = {
    "BENIGN": "N/A",
    "PortScan": "T1046",
    "DDoS": "T1498",
    "Bot": "T1071",
    "Normal": "N/A",
    "Exploits": "T1190",
    "Generic": "T1059",
    "DoS": "T1498",
    "Reconnaissance": "T1595",
    "Fuzzers": "T1499",
    "Analysis": "T1040",
    "Backdoor": "T1059.001",
    "Shellcode": "T1059",
    "Worms": "T1569"
}


def ingest_real_cicids(parquet_path: str = "data/raw/cicids2017_real.parquet") -> pd.DataFrame:
    """Normalize CIC-IDS2017 parquet records into ECS schema."""
    if not os.path.exists(parquet_path):
        print(f"[-] {parquet_path} does not exist.")
        return pd.DataFrame()

    print(f"[*] Normalizing real CIC-IDS2017 flows from {parquet_path}...")
    df = pd.read_parquet(parquet_path)
    
    records = []
    base_time = datetime.datetime(2026, 10, 15, 9, 0, 0)
    
    # Pre-generate simulated internal/external IP pools for network realism
    victim_ips = [f"192.168.10.{i}" for i in range(10, 60)]
    external_ips = [
        "205.174.165.73", "198.51.100.45", "203.0.113.19", 
        "185.220.101.5", "45.33.32.156", "91.240.118.172"
    ]
    
    for idx, row in df.iterrows():
        lbl_str = str(row.get("Label", "BENIGN")).strip()
        is_attack = 0 if lbl_str.upper() in ["BENIGN", "0"] else 1
        
        # Determine endpoints
        if is_attack:
            src_ip = external_ips[idx % len(external_ips)]
            dst_ip = victim_ips[idx % len(victim_ips)]
        else:
            src_ip = victim_ips[idx % len(victim_ips)]
            dst_ip = victim_ips[(idx + 1) % len(victim_ips)]
            
        dst_port = int(row.get("Destination Port", 80))
        src_port = 1024 + (idx % 60000)
        
        # Raw features dictionary for ML / SHAP
        raw_feats = {
            "flow_duration": float(row.get("Flow Duration", 0)),
            "tot_fwd_pkts": float(row.get("Total Fwd Packets", 0)),
            "tot_bwd_pkts": float(row.get("Total Backward Packets", 0)),
            "tot_len_fwd_pkts": float(row.get("Total Length of Fwd Packets", 0)),
            "tot_len_bwd_pkts": float(row.get("Total Length of Bwd Packets", 0)),
            "fwd_pkt_len_mean": float(row.get("Fwd Packet Length Mean", 0)),
            "bwd_pkt_len_mean": float(row.get("Bwd Packet Length Mean", 0)),
            "flow_bytes_s": float(np.nan_to_num(row.get("Flow Bytes/s", 0), nan=0.0, posinf=0.0, neginf=0.0)),
            "flow_pkts_s": float(np.nan_to_num(row.get("Flow Packets/s", 0), nan=0.0, posinf=0.0, neginf=0.0)),
            "syn_flag_cnt": int(row.get("SYN Flag Count", 0)),
            "rst_flag_cnt": int(row.get("RST Flag Count", 0)),
            "psh_flag_cnt": int(row.get("PSH Flag Count", 0)),
            "ack_flag_cnt": int(row.get("ACK Flag Count", 0)),
            "init_win_bytes_fwd": float(row.get("Init_Win_bytes_forward", 0)),
            "init_win_bytes_bwd": float(row.get("Init_Win_bytes_backward", 0))
        }
        
        time_offset = datetime.timedelta(seconds=int(idx * 0.5))
        event_time = (base_time + time_offset).isoformat()
        
        records.append({
            "event_id": f"cicids-{uuid.uuid4().hex[:12]}",
            "timestamp": event_time,
            "layer_source": "network",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "host_id": f"srv-{dst_ip.split('.')[-1]}",
            "user_id": "system",
            "process_name": "suricata" if is_attack else "httpd",
            "process_id": 1000 + (idx % 500),
            "parent_process_id": 1,
            "event_action": "flow_terminated",
            "ground_truth_label": is_attack,
            "attack_category": lbl_str,
            "mitre_technique_id": MITRE_MAPPING.get(lbl_str, "T1046" if is_attack else "N/A"),
            "raw_features_json": json.dumps(raw_feats),
            "is_synthetic": 0
        })

    return pd.DataFrame(records)


def ingest_real_unsw(parquet_path: str = "data/raw/unsw_nb15_real.parquet") -> pd.DataFrame:
    """Normalize UNSW-NB15 parquet records into ECS schema."""
    if not os.path.exists(parquet_path):
        print(f"[-] {parquet_path} does not exist.")
        return pd.DataFrame()

    print(f"[*] Normalizing real UNSW-NB15 flows from {parquet_path}...")
    df = pd.read_parquet(parquet_path)
    
    records = []
    base_time = datetime.datetime(2026, 10, 16, 10, 0, 0)
    
    victim_ips = [f"172.16.0.{i}" for i in range(10, 50)]
    attacker_ips = ["59.166.0.1", "59.166.0.2", "59.166.0.3", "149.171.126.1"]
    
    for idx, row in df.iterrows():
        cat_str = str(row.get("attack_cat", "Normal")).strip()
        is_attack = 0 if cat_str.lower() in ["normal", "0", ""] else 1
        
        if is_attack:
            src_ip = attacker_ips[idx % len(attacker_ips)]
            dst_ip = victim_ips[idx % len(victim_ips)]
        else:
            src_ip = victim_ips[idx % len(victim_ips)]
            dst_ip = victim_ips[(idx + 1) % len(victim_ips)]
            
        proto = str(row.get("proto", "tcp")).upper()
        
        raw_feats = {
            "flow_duration": float(row.get("dur", 0)),
            "tot_fwd_pkts": float(row.get("spkts", 0)),
            "tot_bwd_pkts": float(row.get("dpkts", 0)),
            "tot_len_fwd_pkts": float(row.get("sbytes", 0)),
            "tot_len_bwd_pkts": float(row.get("dbytes", 0)),
            "fwd_pkt_len_mean": float(row.get("sbytes", 0)) / max(float(row.get("spkts", 1)), 1.0),
            "bwd_pkt_len_mean": float(row.get("dbytes", 0)) / max(float(row.get("dpkts", 1)), 1.0),
            "flow_bytes_s": float(np.nan_to_num(row.get("rate", 0), nan=0.0, posinf=0.0, neginf=0.0)),
            "flow_pkts_s": float(np.nan_to_num(row.get("rate", 0) / 100.0, nan=0.0, posinf=0.0, neginf=0.0)),
            "syn_flag_cnt": 1 if "SYN" in str(row.get("state", "")) else 0,
            "rst_flag_cnt": 1 if "RST" in str(row.get("state", "")) else 0,
            "psh_flag_cnt": 0,
            "ack_flag_cnt": 1 if "CON" in str(row.get("state", "")) else 0,
            "init_win_bytes_fwd": 65535.0,
            "init_win_bytes_bwd": 65535.0
        }
        
        time_offset = datetime.timedelta(seconds=int(idx * 0.4))
        event_time = (base_time + time_offset).isoformat()
        
        records.append({
            "event_id": f"unsw-{uuid.uuid4().hex[:12]}",
            "timestamp": event_time,
            "layer_source": "network",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 1024 + (idx % 60000),
            "dst_port": 80 if proto == "TCP" else 53,
            "protocol": proto,
            "host_id": f"gateway-{dst_ip.split('.')[-1]}",
            "user_id": "system",
            "process_name": "zeek" if is_attack else "network_daemon",
            "process_id": 2000 + (idx % 500),
            "parent_process_id": 1,
            "event_action": "flow_analyzed",
            "ground_truth_label": is_attack,
            "attack_category": cat_str,
            "mitre_technique_id": MITRE_MAPPING.get(cat_str, "T1190" if is_attack else "N/A"),
            "raw_features_json": json.dumps(raw_feats),
            "is_synthetic": 0
        })

    return pd.DataFrame(records)


def run_full_real_ingestion(db_path: str = "data/processed/cybervision_ecs.duckdb"):
    """Ingest both real datasets into the DuckDB analytical warehouse."""
    df_cic = ingest_real_cicids()
    df_unsw = ingest_real_unsw()
    
    combined_real = pd.concat([df_cic, df_unsw], ignore_index=True)
    print(f"[+] Total real records prepared: {len(combined_real)}")
    print(f"    - CIC-IDS2017: {len(df_cic)}")
    print(f"    - UNSW-NB15:   {len(df_unsw)}")
    
    conn = duckdb.connect(db_path)
    # Ensure is_synthetic column exists
    cols = [c[0] for c in conn.execute("DESCRIBE ecs_events").fetchall()]
    if "is_synthetic" not in cols:
        conn.execute("ALTER TABLE ecs_events ADD COLUMN is_synthetic INTEGER DEFAULT 1")

    # Clean existing real records to allow idempotent runs
    conn.execute("DELETE FROM ecs_events WHERE is_synthetic = 0")
    
    # Insert new real records
    conn.register("real_records_df", combined_real)
    conn.execute("INSERT INTO ecs_events SELECT * FROM real_records_df")
    
    total = conn.execute("SELECT count(*) FROM ecs_events").fetchone()[0]
    real_cnt = conn.execute("SELECT count(*) FROM ecs_events WHERE is_synthetic = 0").fetchone()[0]
    synth_cnt = conn.execute("SELECT count(*) FROM ecs_events WHERE is_synthetic = 1").fetchone()[0]
    
    print(f"[+] Successfully loaded real events into DuckDB!")
    print(f"    - Total records in DuckDB: {total}")
    print(f"    - Real records: {real_cnt}")
    print(f"    - Synthetic records: {synth_cnt}")
    
    # Export unified parquet
    print("[*] Updating data/processed/ecs_events.parquet with unified data...")
    conn.execute("COPY ecs_events TO 'data/processed/ecs_events.parquet' (FORMAT PARQUET);")
    print("[+] Parquet warehouse updated successfully.")
    conn.close()


if __name__ == "__main__":
    run_full_real_ingestion()

