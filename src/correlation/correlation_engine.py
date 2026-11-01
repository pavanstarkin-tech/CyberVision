"""
Temporal Graph Correlation and Alert Fusion Engine for CyberVision.
Correlates multi-layer alerts into security incidents using sliding temporal windows in NetworkX.
Calculates AFR%, FASR%, Incident Precision/Recall, and Attack Chain Reconstruction Completeness.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
import networkx as nx
import numpy as np

from src.cti.cti_client import ThreatIntelligenceClient


class CrossLayerCorrelationEngine:
    """Graph correlation engine with configurable sliding window and risk weights."""

    def __init__(
        self,
        time_window_minutes: int = 5,
        w1_peak_conf: float = 0.45,
        w2_layer_active: float = 0.25,
        w3_mitre_progression: float = 0.15,
        w4_cti: float = 0.15,
        cti_client: ThreatIntelligenceClient = None
    ):
        self.time_window_minutes = time_window_minutes
        self.w1 = w1_peak_conf
        self.w2 = w2_layer_active
        self.w3 = w3_mitre_progression
        self.w4 = w4_cti
        self.cti_client = cti_client or ThreatIntelligenceClient()

    def correlate_alerts(
        self,
        alerts: List[Dict[str, Any]],
        delta_t_minutes: int = None
    ) -> List[Dict[str, Any]]:
        """
        Groups alerts within a sliding window delta_t_minutes into connected incident graphs.
        """
        if not alerts:
            return []

        win_mins = delta_t_minutes or self.time_window_minutes
        win_seconds = win_mins * 60

        # Sort alerts chronologically
        sorted_alerts = sorted(alerts, key=lambda a: str(a.get("timestamp", "")))

        incidents = []
        incident_counter = 1

        # Build temporal window clusters
        clusters = []
        current_cluster = []

        for alert in sorted_alerts:
            ts_str = alert.get("timestamp")
            try:
                ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)

            if not current_cluster:
                current_cluster.append((ts, alert))
            else:
                first_ts = current_cluster[0][0]
                if (ts - first_ts).total_seconds() <= win_seconds:
                    current_cluster.append((ts, alert))
                else:
                    clusters.append([a[1] for a in current_cluster])
                    current_cluster = [(ts, alert)]

        if current_cluster:
            clusters.append([a[1] for a in current_cluster])

        # In each cluster, connect shared entities into incident graphs
        for cluster in clusters:
            G = nx.Graph()
            for idx, a in enumerate(cluster):
                aid = a.get("event_id", f"a_{idx}")
                G.add_node(aid, node_type="alert", data=a)

                src = a.get("src_ip")
                if src and isinstance(src, str) and src.lower() not in ["none", "nan", ""]:
                    G.add_node(src, node_type="ip")
                    G.add_edge(aid, src)

                dst = a.get("dst_ip")
                if dst and isinstance(dst, str) and dst.lower() not in ["none", "nan", ""]:
                    G.add_node(dst, node_type="ip")
                    G.add_edge(aid, dst)

                host = a.get("host_id")
                if host and isinstance(host, str) and host.lower() not in ["none", "nan", ""]:
                    G.add_node(host, node_type="host")
                    G.add_edge(aid, host)

                user = a.get("user_id")
                if user and isinstance(user, str) and user.lower() not in ["none", "nan", "system"]:
                    G.add_node(user, node_type="user")
                    G.add_edge(aid, user)

            for comp in nx.connected_components(G):
                subG = G.subgraph(comp)
                alert_nodes = [n for n, attr in subG.nodes(data=True) if attr.get("node_type") == "alert"]
                if not alert_nodes:
                    continue

                inc_alerts = [subG.nodes[n]["data"] for n in alert_nodes]
                confidences = [float(a.get("hybrid_confidence", 0.5)) for a in inc_alerts]
                peak_conf = max(confidences) if confidences else 0.5

                distinct_layers = set(a.get("layer_source", "unknown") for a in inc_alerts)
                l_active = min(len(distinct_layers), 3)

                # MITRE progression score
                stages = [int(a.get("stage", 1)) for a in inc_alerts if "stage" in a]
                c_mitre = min(len(set(stages)) * 0.33, 1.0) if stages else 0.4

                # CTI lookup
                involved_ips = set()
                for a in inc_alerts:
                    for ip_key in ["src_ip", "dst_ip"]:
                        val = a.get(ip_key)
                        if val and isinstance(val, str) and val.lower() not in ["none", "nan", ""]:
                            involved_ips.add(val)

                cti_reps = [self.cti_client.check_ip_reputation(ip)["reputation_score"] for ip in involved_ips]
                i_cti = max(cti_reps) if cti_reps else 0.0

                risk_val = (
                    self.w1 * peak_conf +
                    self.w2 * (l_active / 3.0) +
                    self.w3 * c_mitre +
                    self.w4 * i_cti
                )
                risk_score = round(float(np.clip(risk_val, 0.0, 1.0) * 100.0), 2)

                if risk_score >= 90.0:
                    sev = "Critical"
                elif risk_score >= 70.0:
                    sev = "High"
                elif risk_score >= 40.0:
                    sev = "Medium"
                else:
                    sev = "Low"

                entities = [n for n, attr in subG.nodes(data=True) if attr.get("node_type") != "alert"]

                incidents.append({
                    "incident_id": f"INC-2026-{incident_counter:04d}",
                    "severity": sev,
                    "risk_score": risk_score,
                    "corroborating_layers": list(distinct_layers),
                    "num_layers_active": l_active,
                    "peak_confidence": round(peak_conf, 4),
                    "cti_reputation": round(i_cti, 4),
                    "num_alerts": len(inc_alerts),
                    "associated_entities": entities,
                    "alerts": inc_alerts,
                    "first_seen": inc_alerts[0].get("timestamp"),
                    "last_seen": inc_alerts[-1].get("timestamp")
                })
                incident_counter += 1

        incidents.sort(key=lambda x: x["risk_score"], reverse=True)
        return incidents

    @staticmethod
    def evaluate_campaign_correlation(
        raw_alerts: List[Dict[str, Any]],
        incidents: List[Dict[str, Any]],
        ground_truth_campaigns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Computes exact statistical metrics across campaigns:
        - Raw Alerts & FP count
        - Correlated Incidents & Post-Correlation FPs
        - AFR % & FASR %
        - Incident-Level Precision and Recall
        - Multi-Stage Attack Chain Reconstruction Completeness (%)
        """
        n_raw = len(raw_alerts)
        n_inc = len(incidents)

        raw_fps = sum(1 for a in raw_alerts if a.get("ground_truth_label", 0) == 0)

        # High/Critical incidents that contain no true malicious alerts are correlated FPs
        correlated_fps = sum(
            1 for inc in incidents
            if inc["severity"] in ["High", "Critical"] and all(a.get("ground_truth_label", 0) == 0 for a in inc["alerts"])
        )

        afr = (1.0 - (n_inc / max(n_raw, 1))) * 100.0
        fasr = ((raw_fps - correlated_fps) / max(raw_fps, 1)) * 100.0 if raw_fps > 0 else 100.0

        # Ground truth campaign chain completeness
        reconstructed_stages = 0
        total_possible_stages = len(ground_truth_campaigns) * 3
        detected_campaigns = 0

        for gt in ground_truth_campaigns:
            cid = gt["campaign_id"]
            # Find all incidents containing alerts from this campaign
            matching_alerts = []
            for inc in incidents:
                for a in inc["alerts"]:
                    if a.get("campaign_id") == cid:
                        matching_alerts.append(a)

            if matching_alerts:
                detected_campaigns += 1
                stages_found = len(set(a.get("stage", 1) for a in matching_alerts))
                reconstructed_stages += stages_found

        chain_completeness = (reconstructed_stages / max(total_possible_stages, 1)) * 100.0
        campaign_recall = (detected_campaigns / max(len(ground_truth_campaigns), 1)) * 100.0

        # Incident Precision: percentage of High/Critical incidents that contain true campaign alerts
        high_crit_inc = [inc for inc in incidents if inc["severity"] in ["High", "Critical"]]
        true_high_crit = sum(1 for inc in high_crit_inc if any(a.get("ground_truth_label", 0) == 1 for a in inc["alerts"]))
        inc_precision = (true_high_crit / max(len(high_crit_inc), 1)) * 100.0

        return {
            "raw_alerts": n_raw,
            "raw_fps": raw_fps,
            "correlated_incidents": n_inc,
            "post_corr_fps": correlated_fps,
            "afr_pct": round(max(afr, 0.0), 2),
            "fasr_pct": round(min(max(fasr, 0.0), 100.0), 2),
            "incident_precision_pct": round(inc_precision, 2),
            "incident_recall_pct": round(campaign_recall, 2),
            "chain_completeness_pct": round(chain_completeness, 2)
        }
