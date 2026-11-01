"""
Multi-Stage Attack Campaign Generator for CyberVision.
Synthesizes 50 distinct multi-layer attack campaigns (Network Ingress -> Host PrivEsc -> User Exfiltration)
embedded within background single-layer enterprise noise to benchmark graph correlation.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Tuple
import numpy as np
import uuid


class ScenarioBuilder:
    """Builds 50 distinct multi-stage attack campaigns across synchronized entities."""

    @staticmethod
    def build_50_attack_campaigns(
        n_campaigns: int = 50,
        n_background_noise: int = 2000,
        start_time: datetime = None,
        random_seed: int = 42
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Creates 50 distinct 3-stage intrusion campaigns:
        - Stage 1 (Network): Brute-Force / Exploit targeting Host_X:port from Attacker_IP
        - Stage 2 (Host): Kernel setuid(0) / namespace escape on Host_X
        - Stage 3 (User): Off-hours exfiltration / USB write by User_Y on Host_X
        Also generates n_background_noise single-layer benign and false-positive alerts.
        """
        rng = np.random.RandomState(random_seed)
        if start_time is None:
            start_time = datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc)

        all_campaign_events = []
        ground_truth_campaigns = []

        # 1. Generate 50 Campaigns
        for cid in range(1, n_campaigns + 1):
            camp_id = f"CAMP-2026-{cid:04d}"
            host_target = f"host-192.168.10.{rng.randint(10, 90)}"
            attacker_ip = f"205.174.165.{rng.randint(50, 99)}"
            compromised_user = f"user_{rng.randint(1, 30)}"
            base_t = start_time + timedelta(minutes=cid * 4 + rng.uniform(-1, 1))

            # Stage 1: Network Ingress
            t1 = base_t
            ev1 = {
                "event_id": str(uuid.uuid4()),
                "campaign_id": camp_id,
                "stage": 1,
                "timestamp": t1.isoformat(),
                "layer_source": "network",
                "src_ip": attacker_ip,
                "dst_ip": host_target.replace("host-", ""),
                "host_id": host_target,
                "user_id": "system",
                "attack_category": rng.choice(["SSH_Patator", "FTP_Patator", "Web_SQLi_XSS"]),
                "hybrid_confidence": float(rng.uniform(0.92, 0.99)),
                "ground_truth_label": 1,
                "mitre_technique_id": "T1110.001"
            }

            # Stage 2: Host Privilege Escalation (within 1 to 3 minutes)
            t2 = t1 + timedelta(seconds=rng.uniform(45, 120))
            ev2 = {
                "event_id": str(uuid.uuid4()),
                "campaign_id": camp_id,
                "stage": 2,
                "timestamp": t2.isoformat(),
                "layer_source": "host",
                "src_ip": host_target.replace("host-", ""),
                "dst_ip": host_target.replace("host-", ""),
                "host_id": host_target,
                "user_id": compromised_user,
                "process_name": rng.choice(["setuid_helper", "nsenter", "bash"]),
                "attack_category": rng.choice(["Kernel_PrivEsc_Setuid", "Container_Namespace_Escape", "Suspicious_Child_Spawn"]),
                "hybrid_confidence": float(rng.uniform(0.90, 0.98)),
                "ground_truth_label": 1,
                "mitre_technique_id": "T1548"
            }

            # Stage 3: User Exfiltration (within 1 to 3 minutes of stage 2)
            t3 = t2 + timedelta(seconds=rng.uniform(60, 150))
            ev3 = {
                "event_id": str(uuid.uuid4()),
                "campaign_id": camp_id,
                "stage": 3,
                "timestamp": t3.isoformat(),
                "layer_source": "application",
                "src_ip": host_target.replace("host-", ""),
                "dst_ip": "198.51.100.24",
                "host_id": host_target,
                "user_id": compromised_user,
                "process_name": "curl",
                "attack_category": rng.choice(["OffHours_Logon_Burst", "Removable_USB_Exfil", "Cloud_Staging_Exfil"]),
                "hybrid_confidence": float(rng.uniform(0.91, 0.99)),
                "ground_truth_label": 1,
                "mitre_technique_id": "T1048"
            }

            camp_events = [ev1, ev2, ev3]
            all_campaign_events.extend(camp_events)
            ground_truth_campaigns.append({
                "campaign_id": camp_id,
                "event_ids": [ev1["event_id"], ev2["event_id"], ev3["event_id"]],
                "host_id": host_target,
                "user_id": compromised_user,
                "attacker_ip": attacker_ip
            })

        # 2. Generate Background Single-Layer False-Positive Alerts
        background_alerts = []
        for bid in range(n_background_noise):
            layer = rng.choice(["network", "host", "application"], p=[0.55, 0.25, 0.20])
            t_bg = start_time + timedelta(seconds=rng.uniform(0, n_campaigns * 240))
            h_bg = f"host-192.168.10.{rng.randint(100, 250)}" # Isolated benign hosts
            u_bg = f"user_{rng.randint(50, 100)}"
            bg_ev = {
                "event_id": str(uuid.uuid4()),
                "campaign_id": "NOISE",
                "stage": 0,
                "timestamp": t_bg.isoformat(),
                "layer_source": layer,
                "src_ip": f"192.168.10.{rng.randint(10, 80)}" if layer == "network" else h_bg.replace("host-", ""),
                "dst_ip": h_bg.replace("host-", ""),
                "host_id": h_bg,
                "user_id": u_bg,
                "process_name": "systemd",
                "attack_category": "Benign_Noise_Burst",
                "hybrid_confidence": float(rng.uniform(0.50, 0.68)), # False positive threshold crossers
                "ground_truth_label": 0,
                "mitre_technique_id": "T0000"
            }
            background_alerts.append(bg_ev)

        total_alerts = all_campaign_events + background_alerts
        total_alerts.sort(key=lambda x: x["timestamp"])

        return total_alerts, ground_truth_campaigns
