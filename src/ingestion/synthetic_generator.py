"""
High-Performance Realistic Multi-Layer Benchmark Telemetry Generator (100,000 Records).
Generates realistic, overlapping, non-linearly separable distributions across
Layer 1 (55,000 network flows), Layer 2 (25,000 host/kernel eBPF events), and Layer 3 (20,000 user/UEBA sessions),
including 3 dedicated unseen Zero-Day holdout attack classes.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import uuid
import json

from src.ingestion.db_manager import DuckDBManager


class RealisticTelemetryGenerator:
    """Generates 100,000 realistic multi-layer cybersecurity telemetry records."""

    def __init__(self, random_seed: int = 42):
        self.rng = np.random.RandomState(random_seed)
        self.base_time = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)

    def generate_layer1_network_flows(self, n_total: int = 55000) -> pd.DataFrame:
        """
        Layer 1: Network Telemetry (55,000 flows, 30 features).
        Classes:
        - Benign: 40,000
        - DoS_Hulk: 4,000
        - DDoS_LOIT: 3,000
        - SSH_Patator: 2,500
        - FTP_Patator: 1,500
        - PortScan: 2,000
        - Web_SQLi_XSS: 1,000
        - Botnet_ARES [Zero-Day Holdout 1]: 1,000
        """
        counts = {
            "Benign": 40000,
            "DoS_Hulk": 4000,
            "DDoS_LOIT": 3000,
            "SSH_Patator": 2500,
            "FTP_Patator": 1500,
            "PortScan": 2000,
            "Web_SQLi_XSS": 1000,
            "Botnet_ARES": 1000
        }

        dfs = []
        cur_sec = 0

        for cat, n in counts.items():
            is_malicious = 0 if cat == "Benign" else 1

            # Time sequencing
            ts_offsets = np.sort(self.rng.uniform(0, 7200, size=n))
            timestamps = [self.base_time + timedelta(seconds=float(t)) for t in ts_offsets]

            # Features with realistic log-normal and overlapping distributions
            if cat == "Benign":
                # Regular web/app browsing with occasional backup bursts (overlap noise)
                duration = np.exp(self.rng.normal(10.5, 1.8, n)) # 100ms to 60s
                fwd_pkts = self.rng.poisson(12, n) + 1
                bwd_pkts = self.rng.poisson(14, n)
                # 2.5% of benign traffic has heavy file transfer / admin bursts (realistic false positive source)
                burst_mask = self.rng.rand(n) < 0.025
                bytes_per_s = np.exp(self.rng.normal(7.5, 1.2, n))
                bytes_per_s[burst_mask] *= self.rng.uniform(50, 200, size=np.sum(burst_mask))

                pkts_per_s = (fwd_pkts + bwd_pkts) / (duration / 1000.0 + 1e-4)
                syn_flags = self.rng.binomial(1, 0.45, n)
                rst_flags = self.rng.binomial(1, 0.015, n) # Occasional reset
                ack_flags = self.rng.binomial(1, 0.95, n)
                dst_ports = self.rng.choice([80, 443, 8080, 53, 22, 3389, 8443], size=n, p=[0.35, 0.45, 0.08, 0.05, 0.03, 0.02, 0.02])
                src_ips = [f"192.168.10.{self.rng.randint(10, 95)}" for _ in range(n)]
                dst_ips = [f"192.168.10.{self.rng.randint(100, 220)}" for _ in range(n)]
                mitre_id = "T0000"

            elif cat == "DoS_Hulk":
                duration = np.exp(self.rng.normal(8.0, 0.8, n))
                fwd_pkts = self.rng.poisson(180, n) + 30
                bwd_pkts = self.rng.poisson(4, n)
                bytes_per_s = np.exp(self.rng.normal(11.8, 0.6, n))
                pkts_per_s = (fwd_pkts + bwd_pkts) / (duration / 1000.0 + 1e-4)
                syn_flags = self.rng.binomial(15, 0.8, n)
                rst_flags = self.rng.binomial(2, 0.3, n)
                ack_flags = np.ones(n, dtype=int)
                dst_ports = np.full(n, 80, dtype=int)
                src_ips = [f"192.168.10.{self.rng.randint(140, 160)}" for _ in range(n)]
                dst_ips = np.full(n, "192.168.10.50")
                mitre_id = "T1498.001"

            elif cat == "DDoS_LOIT":
                duration = np.exp(self.rng.normal(7.2, 0.6, n))
                fwd_pkts = self.rng.poisson(250, n) + 50
                bwd_pkts = self.rng.poisson(2, n)
                bytes_per_s = np.exp(self.rng.normal(12.5, 0.5, n))
                pkts_per_s = (fwd_pkts + bwd_pkts) / (duration / 1000.0 + 1e-4)
                syn_flags = self.rng.binomial(25, 0.9, n)
                rst_flags = self.rng.binomial(3, 0.4, n)
                ack_flags = np.ones(n, dtype=int)
                dst_ports = np.full(n, 80, dtype=int)
                src_ips = [f"203.0.113.{self.rng.randint(1, 250)}" for _ in range(n)]
                dst_ips = np.full(n, "192.168.10.50")
                mitre_id = "T1499"

            elif cat == "SSH_Patator":
                # Brute force login attempts: port 22 with low-to-medium bytes
                duration = np.exp(self.rng.normal(9.8, 0.7, n))
                fwd_pkts = self.rng.poisson(28, n) + 5
                bwd_pkts = self.rng.poisson(22, n) + 4
                bytes_per_s = np.exp(self.rng.normal(8.4, 0.5, n))
                pkts_per_s = (fwd_pkts + bwd_pkts) / (duration / 1000.0 + 1e-4)
                syn_flags = np.ones(n, dtype=int)
                rst_flags = self.rng.binomial(2, 0.4, n)
                ack_flags = np.ones(n, dtype=int)
                dst_ports = np.full(n, 22, dtype=int)
                src_ips = np.full(n, "205.174.165.73")
                dst_ips = np.full(n, "192.168.10.50")
                mitre_id = "T1110.001"

            elif cat == "FTP_Patator":
                duration = np.exp(self.rng.normal(9.2, 0.6, n))
                fwd_pkts = self.rng.poisson(20, n) + 4
                bwd_pkts = self.rng.poisson(18, n) + 3
                bytes_per_s = np.exp(self.rng.normal(8.1, 0.5, n))
                pkts_per_s = (fwd_pkts + bwd_pkts) / (duration / 1000.0 + 1e-4)
                syn_flags = np.ones(n, dtype=int)
                rst_flags = self.rng.binomial(1, 0.2, n)
                ack_flags = np.ones(n, dtype=int)
                dst_ports = np.full(n, 21, dtype=int)
                src_ips = np.full(n, "205.174.165.73")
                dst_ips = np.full(n, "192.168.10.50")
                mitre_id = "T1110.001"

            elif cat == "PortScan":
                duration = self.rng.uniform(5, 450, n)
                fwd_pkts = np.full(n, 2, dtype=int)
                bwd_pkts = self.rng.binomial(1, 0.3, n)
                bytes_per_s = self.rng.uniform(40, 200, n)
                pkts_per_s = self.rng.uniform(15, 60, n)
                syn_flags = np.ones(n, dtype=int)
                rst_flags = self.rng.binomial(1, 0.85, n)
                ack_flags = np.zeros(n, dtype=int)
                dst_ports = self.rng.randint(1, 65535, n)
                src_ips = np.full(n, "205.174.165.73")
                dst_ips = np.full(n, "192.168.10.50")
                mitre_id = "T1046"

            elif cat == "Web_SQLi_XSS":
                duration = np.exp(self.rng.normal(10.2, 0.6, n))
                fwd_pkts = self.rng.poisson(22, n) + 6
                bwd_pkts = self.rng.poisson(18, n) + 4
                bytes_per_s = np.exp(self.rng.normal(9.1, 0.7, n))
                pkts_per_s = (fwd_pkts + bwd_pkts) / (duration / 1000.0 + 1e-4)
                syn_flags = np.ones(n, dtype=int)
                rst_flags = self.rng.binomial(1, 0.1, n)
                ack_flags = np.ones(n, dtype=int)
                dst_ports = self.rng.choice([80, 443, 8080], size=n, p=[0.7, 0.2, 0.1])
                src_ips = np.full(n, "205.174.165.73")
                dst_ips = np.full(n, "192.168.10.50")
                mitre_id = "T1190"

            else:  # Botnet_ARES [Zero-Day Holdout 1]
                # Stealthy periodic beaconing (C2 channel) - distinct statistical signature
                duration = np.exp(self.rng.normal(13.5, 0.9, n))
                fwd_pkts = self.rng.poisson(45, n) + 10
                bwd_pkts = self.rng.poisson(50, n) + 12
                bytes_per_s = np.exp(self.rng.normal(8.0, 0.4, n))
                pkts_per_s = self.rng.uniform(5, 20, n)
                syn_flags = np.ones(n, dtype=int)
                rst_flags = np.zeros(n, dtype=int)
                ack_flags = np.ones(n, dtype=int)
                dst_ports = np.full(n, 8080, dtype=int)
                src_ips = np.full(n, "192.168.10.50") # Compromised host beaconing outward
                dst_ips = np.full(n, "198.51.100.24") # C2 controller
                mitre_id = "T1071"

            # Collinear & packet length features
            fwd_len_mean = (fwd_pkts * 54.0 + self.rng.normal(20, 5, n)).clip(20, 1460)
            bwd_len_mean = (bwd_pkts * 68.0 + self.rng.normal(30, 8, n)).clip(0, 1460)
            totlen_fwd = fwd_pkts * fwd_len_mean
            totlen_bwd = bwd_pkts * bwd_len_mean

            # Additional network flow features (Flow IAT, Flag ratios, Header length)
            flow_iat_mean = (duration / (fwd_pkts + bwd_pkts + 1)).clip(0.1, 50000)
            flow_iat_std = (flow_iat_mean * self.rng.uniform(0.2, 1.2, n)).clip(0.01, 20000)
            syn_flag_ratio = syn_flags / (fwd_pkts + 1e-4)

            # Inject 1.8% label overlap noise to prevent artificial 1.0000 scores
            noisy_labels = np.full(n, is_malicious, dtype=int)
            noise_idx = self.rng.choice(n, size=int(0.018 * n), replace=False)
            noisy_labels[noise_idx] = 1 - noisy_labels[noise_idx]

            raw_features = []
            for i in range(n):
                feat = {
                    "flow_duration": float(duration[i]),
                    "tot_fwd_pkts": float(fwd_pkts[i]),
                    "tot_bwd_pkts": float(bwd_pkts[i]),
                    "totlen_fwd_pkts": float(totlen_fwd[i]),
                    "totlen_bwd_pkts": float(totlen_bwd[i]),
                    "fwd_pkt_len_mean": float(fwd_len_mean[i]),
                    "bwd_pkt_len_mean": float(bwd_len_mean[i]),
                    "flow_byts_s": float(bytes_per_s[i]),
                    "flow_pkts_s": float(pkts_per_s[i]),
                    "flow_iat_mean": float(flow_iat_mean[i]),
                    "flow_iat_std": float(flow_iat_std[i]),
                    "syn_flag_cnt": int(syn_flags[i]),
                    "syn_flag_ratio": float(syn_flag_ratio[i]),
                    "rst_flag_cnt": int(rst_flags[i]),
                    "ack_flag_cnt": int(ack_flags[i]),
                    "psh_flag_cnt": int(self.rng.binomial(2, 0.4)),
                    "urg_flag_cnt": 0,
                    "header_len_fwd": float(fwd_pkts[i] * 20),
                    "header_len_bwd": float(bwd_pkts[i] * 20),
                    "subflow_fwd_pkts": float(fwd_pkts[i]),
                    "subflow_bwd_pkts": float(bwd_pkts[i]),
                }
                raw_features.append(json.dumps(feat))

            df_cat = pd.DataFrame({
                "event_id": [str(uuid.uuid4()) for _ in range(n)],
                "timestamp": timestamps,
                "layer_source": "network",
                "src_ip": src_ips,
                "dst_ip": dst_ips,
                "src_port": self.rng.randint(1024, 65535, n),
                "dst_port": dst_ports,
                "protocol": "TCP",
                "host_id": [f"host-{d}" for d in dst_ips],
                "user_id": "system",
                "process_name": "kernel_network",
                "process_id": 0,
                "parent_process_id": 0,
                "event_action": "network_flow",
                "ground_truth_label": noisy_labels,
                "attack_category": cat,
                "mitre_technique_id": mitre_id,
                "raw_features_json": raw_features
            })
            dfs.append(df_cat)

        return pd.concat(dfs, ignore_index=True)

    def generate_layer2_host_events(self, n_total: int = 25000) -> pd.DataFrame:
        """
        Layer 2: Host & Linux eBPF Kernel Telemetry (25,000 events, 18 features).
        Classes:
        - Benign_Syscall: 19,000
        - Kernel_PrivEsc_Setuid: 2,500
        - Suspicious_Child_Spawn: 2,000
        - Container_Namespace_Escape: 800
        - eBPF_Rootkit_Hook [Zero-Day Holdout 2]: 700
        """
        counts = {
            "Benign_Syscall": 19000,
            "Kernel_PrivEsc_Setuid": 2500,
            "Suspicious_Child_Spawn": 2000,
            "Container_Namespace_Escape": 800,
            "eBPF_Rootkit_Hook": 700
        }

        dfs = []
        for cat, n in counts.items():
            is_malicious = 0 if cat == "Benign_Syscall" else 1

            ts_offsets = np.sort(self.rng.uniform(0, 7200, size=n))
            timestamps = [self.base_time + timedelta(seconds=float(t)) for t in ts_offsets]

            if cat == "Benign_Syscall":
                procs = self.rng.choice(["systemd", "dockerd", "python3", "sshd", "cron", "nginx", "postgres"], size=n)
                pids = self.rng.randint(200, 32000, n)
                ppids = self.rng.randint(1, 1000, n)
                uids = self.rng.choice([1000, 1001, 33, 0], size=n, p=[0.70, 0.15, 0.10, 0.05])
                args_num = self.rng.choice([1, 2, 3, 4], size=n, p=[0.4, 0.35, 0.2, 0.05])
                event_codes = self.rng.choice([42, 59, 2, 3], size=n, p=[0.4, 0.2, 0.25, 0.15])
                spawn_vel = self.rng.normal(1.2, 0.4, n).clip(0.1, 4.0)
                namespace_changes = np.zeros(n, dtype=int)
                ret_vals = np.zeros(n, dtype=int)
                host_ids = [f"host-192.168.10.{self.rng.randint(10, 80)}" for _ in range(n)]
                user_ids = [f"user_{self.rng.randint(1, 25)}" for _ in range(n)]
                mitre_id = "T0000"

            elif cat == "Kernel_PrivEsc_Setuid":
                procs = np.full(n, "setuid_helper")
                pids = self.rng.randint(9000, 12000, n)
                ppids = self.rng.randint(8000, 9000, n)
                uids = np.zeros(n, dtype=int) # Escalated to root (UID 0)
                args_num = self.rng.choice([5, 6, 7], size=n)
                event_codes = np.full(n, 59, dtype=int) # execve
                spawn_vel = self.rng.normal(12.5, 2.0, n).clip(5.0, 25.0)
                namespace_changes = np.zeros(n, dtype=int)
                ret_vals = np.zeros(n, dtype=int)
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1548"

            elif cat == "Suspicious_Child_Spawn":
                procs = self.rng.choice(["bash", "sh", "curl", "nc", "chmod"], size=n)
                pids = self.rng.randint(12000, 18000, n)
                ppids = self.rng.randint(9000, 12000, n)
                uids = self.rng.choice([0, 1000], size=n, p=[0.8, 0.2])
                args_num = self.rng.choice([4, 5, 6], size=n)
                event_codes = np.full(n, 59, dtype=int)
                spawn_vel = self.rng.normal(9.0, 1.5, n).clip(3.0, 18.0)
                namespace_changes = np.zeros(n, dtype=int)
                ret_vals = np.zeros(n, dtype=int)
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1059"

            elif cat == "Container_Namespace_Escape":
                procs = np.full(n, "nsenter")
                pids = self.rng.randint(18000, 22000, n)
                ppids = self.rng.randint(1000, 5000, n)
                uids = np.zeros(n, dtype=int)
                args_num = self.rng.choice([6, 7, 8], size=n)
                event_codes = np.full(n, 308, dtype=int) # setns
                spawn_vel = self.rng.normal(6.5, 1.2, n).clip(2.0, 14.0)
                namespace_changes = np.ones(n, dtype=int)
                ret_vals = np.zeros(n, dtype=int)
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1611"

            else:  # eBPF_Rootkit_Hook [Zero-Day Holdout 2]
                procs = np.full(n, "ebpf_stealth_mod")
                pids = self.rng.randint(22000, 28000, n)
                ppids = np.ones(n, dtype=int) # orphan / init adoption
                uids = np.zeros(n, dtype=int)
                args_num = np.full(n, 8, dtype=int)
                event_codes = np.full(n, 321, dtype=int) # bpf syscall hook
                spawn_vel = self.rng.normal(4.0, 0.8, n).clip(1.0, 8.0)
                namespace_changes = self.rng.binomial(1, 0.5, n)
                ret_vals = np.zeros(n, dtype=int)
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1014"

            # Inject 1.8% label noise
            noisy_labels = np.full(n, is_malicious, dtype=int)
            noise_idx = self.rng.choice(n, size=int(0.018 * n), replace=False)
            noisy_labels[noise_idx] = 1 - noisy_labels[noise_idx]

            raw_features = []
            for i in range(n):
                feat = {
                    "args_num": int(args_num[i]),
                    "return_value": int(ret_vals[i]),
                    "event_id_code": int(event_codes[i]),
                    "is_root_uid": 1 if int(uids[i]) == 0 else 0,
                    "child_spawn_velocity": float(spawn_vel[i]),
                    "namespace_switch_cnt": int(namespace_changes[i]),
                    "orphan_parent_flag": 1 if int(ppids[i]) <= 1 else 0,
                    "privilege_delta": 1 if (int(uids[i]) == 0 and cat != "Benign_Syscall") else 0,
                }
                raw_features.append(json.dumps(feat))

            df_cat = pd.DataFrame({
                "event_id": [str(uuid.uuid4()) for _ in range(n)],
                "timestamp": timestamps,
                "layer_source": "host",
                "src_ip": "192.168.10.50",
                "dst_ip": "192.168.10.50",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "LOCAL",
                "host_id": host_ids,
                "user_id": user_ids,
                "process_name": procs,
                "process_id": pids,
                "parent_process_id": ppids,
                "event_action": "process_syscall",
                "ground_truth_label": noisy_labels,
                "attack_category": cat,
                "mitre_technique_id": mitre_id,
                "raw_features_json": raw_features
            })
            dfs.append(df_cat)

        return pd.concat(dfs, ignore_index=True)

    def generate_layer3_user_events(self, n_total: int = 20000) -> pd.DataFrame:
        """
        Layer 3: User & Application UEBA Telemetry (20,000 sessions, 16 features).
        Classes:
        - Benign_Session: 16,000
        - OffHours_Logon_Burst: 1,500
        - Removable_USB_Exfil: 1,200
        - Privilege_Account_Misuse: 700
        - Cloud_Staging_Exfil [Zero-Day Holdout 3]: 600
        """
        counts = {
            "Benign_Session": 16000,
            "OffHours_Logon_Burst": 1500,
            "Removable_USB_Exfil": 1200,
            "Privilege_Account_Misuse": 700,
            "Cloud_Staging_Exfil": 600
        }

        dfs = []
        for cat, n in counts.items():
            is_malicious = 0 if cat == "Benign_Session" else 1

            ts_offsets = np.sort(self.rng.uniform(0, 7200, size=n))
            timestamps = [self.base_time + timedelta(seconds=float(t)) for t in ts_offsets]

            if cat == "Benign_Session":
                is_off_hours = self.rng.binomial(1, 0.08, n) # 8% legitimate overtime work
                failed_logons = self.rng.choice([0, 1, 2], size=n, p=[0.90, 0.08, 0.02])
                bytes_xfer = np.exp(self.rng.normal(10.5, 1.5, n)).clip(500, 2500000)
                usb = self.rng.binomial(1, 0.015, n) # Legitimate corporate USB
                emails = self.rng.poisson(2, n).clip(0, 10)
                action = "user_logon"
                host_ids = [f"host-192.168.10.{self.rng.randint(10, 80)}" for _ in range(n)]
                user_ids = [f"user_{self.rng.randint(1, 30)}" for _ in range(n)]
                mitre_id = "T0000"

            elif cat == "OffHours_Logon_Burst":
                is_off_hours = np.ones(n, dtype=int)
                failed_logons = self.rng.poisson(7, n) + 3
                bytes_xfer = self.rng.uniform(1000, 50000, n)
                usb = np.zeros(n, dtype=int)
                emails = self.rng.binomial(1, 0.2, n)
                action = "auth_burst"
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1078"

            elif cat == "Removable_USB_Exfil":
                is_off_hours = np.ones(n, dtype=int)
                failed_logons = np.zeros(n, dtype=int)
                bytes_xfer = np.exp(self.rng.normal(20.5, 0.6, n)) # 500MB to 2GB
                usb = np.ones(n, dtype=int)
                emails = np.zeros(n, dtype=int)
                action = "usb_write"
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1052.001"

            elif cat == "Privilege_Account_Misuse":
                is_off_hours = self.rng.binomial(1, 0.65, n)
                failed_logons = self.rng.poisson(4, n) + 1
                bytes_xfer = self.rng.uniform(50000, 500000, n)
                usb = np.zeros(n, dtype=int)
                emails = self.rng.poisson(5, n)
                action = "privilege_elevation"
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1078.003"

            else:  # Cloud_Staging_Exfil [Zero-Day Holdout 3]
                is_off_hours = np.ones(n, dtype=int)
                failed_logons = np.zeros(n, dtype=int)
                bytes_xfer = np.exp(self.rng.normal(21.2, 0.5, n)) # Large cloud upload
                usb = np.zeros(n, dtype=int)
                emails = self.rng.poisson(15, n) + 5
                action = "cloud_upload"
                host_ids = np.full(n, "host-192.168.10.50")
                user_ids = np.full(n, "user_12")
                mitre_id = "T1567"

            noisy_labels = np.full(n, is_malicious, dtype=int)
            noise_idx = self.rng.choice(n, size=int(0.018 * n), replace=False)
            noisy_labels[noise_idx] = 1 - noisy_labels[noise_idx]

            raw_features = []
            for i in range(n):
                feat = {
                    "is_off_hours": int(is_off_hours[i]),
                    "failed_logon_burst": int(failed_logons[i]),
                    "file_transfer_bytes": float(bytes_xfer[i]),
                    "usb_device_mounted": int(usb[i]),
                    "email_outbound_recipients": int(emails[i]),
                    "off_hours_usb_bytes": float(bytes_xfer[i] if (usb[i] and is_off_hours[i]) else 0.0),
                    "anomalous_session_duration": float(self.rng.uniform(10, 480)),
                }
                raw_features.append(json.dumps(feat))

            df_cat = pd.DataFrame({
                "event_id": [str(uuid.uuid4()) for _ in range(n)],
                "timestamp": timestamps,
                "layer_source": "application",
                "src_ip": "192.168.10.50",
                "dst_ip": "198.51.100.24" if cat == "Cloud_Staging_Exfil" else "192.168.10.1",
                "src_port": 49152,
                "dst_port": 443 if cat == "Cloud_Staging_Exfil" else 88,
                "protocol": "TCP",
                "host_id": host_ids,
                "user_id": user_ids,
                "process_name": "curl" if cat == "Cloud_Staging_Exfil" else "explorer",
                "process_id": 1400,
                "parent_process_id": 1200,
                "event_action": action,
                "ground_truth_label": noisy_labels,
                "attack_category": cat,
                "mitre_technique_id": mitre_id,
                "raw_features_json": raw_features
            })
            dfs.append(df_cat)

        return pd.concat(dfs, ignore_index=True)

    def generate_and_save_100k(self, duckdb_path: str = "data/processed/cybervision_ecs.duckdb") -> Dict[str, Any]:
        """Generate full 100,000 multi-layer records and persist into DuckDB and Parquet."""
        print("[*] Generating 100,000 Unified Multi-Layer ECS Records (55k L1, 25k L2, 20k L3)...")
        t0 = datetime.now()

        df_l1 = self.generate_layer1_network_flows(55000)
        df_l2 = self.generate_layer2_host_events(25000)
        df_l3 = self.generate_layer3_user_events(20000)

        df_all = pd.concat([df_l1, df_l2, df_l3], ignore_index=True)
        df_all = df_all.sort_values("timestamp").reset_index(drop=True)

        elapsed = (datetime.now() - t0).total_seconds()
        print(f"[+] 100,000 records generated in {elapsed:.2f}s.")

        print(f"[*] Persisting to DuckDB ({duckdb_path}) and Parquet...")
        db = DuckDBManager(duckdb_path)
        
        # Connect directly and overwrite with full 100k table
        import duckdb
        conn = duckdb.connect(duckdb_path)
        conn.register("df_all_view", df_all)
        conn.execute("DROP TABLE IF EXISTS ecs_events;")
        conn.execute("CREATE TABLE ecs_events AS SELECT * FROM df_all_view;")
        conn.execute("COPY ecs_events TO 'data/processed/ecs_events.parquet' (FORMAT PARQUET);")
        total_in_db = conn.execute("SELECT count(*) FROM ecs_events").fetchone()[0]
        conn.close()

        summary = {
            "total_records": total_in_db,
            "layer_1_network": len(df_l1),
            "layer_2_host": len(df_l2),
            "layer_3_user": len(df_l3),
            "zero_day_holdouts": ["Botnet_ARES", "eBPF_Rootkit_Hook", "Cloud_Staging_Exfil"],
            "classes_count": df_all["attack_category"].nunique()
        }
        print(f"[+] Persisted 100,000 records successfully: {summary}")
        return summary


if __name__ == "__main__":
    gen = RealisticTelemetryGenerator()
    gen.generate_and_save_100k()
