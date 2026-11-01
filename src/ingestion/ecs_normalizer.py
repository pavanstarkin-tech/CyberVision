"""
Unified Log Normalization Engine for CyberVision.
Maps heterogeneous logs across Layer 1 (Network), Layer 2 (Host), and Layer 3 (User/UEBA)
into canonical Elastic Common Schema (ECS) compliant records using Pydantic.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
import uuid
import json
from pydantic import BaseModel, Field, field_validator


class ECSLogRecord(BaseModel):
    """Canonical Unified Log Schema based on Elastic Common Schema (ECS)."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    layer_source: str = Field(..., description="'network' | 'host' | 'application'")
    
    # Network Layer (L1)
    src_ip: Optional[str] = Field(default=None)
    dst_ip: Optional[str] = Field(default=None)
    src_port: Optional[int] = Field(default=None)
    dst_port: Optional[int] = Field(default=None)
    protocol: Optional[str] = Field(default=None)
    
    # Host & Process Layer (L2)
    host_id: Optional[str] = Field(default=None)
    user_id: Optional[str] = Field(default=None)
    process_name: Optional[str] = Field(default=None)
    process_id: Optional[int] = Field(default=None)
    parent_process_id: Optional[int] = Field(default=None)
    
    # Action & Features
    event_action: str = Field(default="unknown")
    raw_features: Dict[str, Any] = Field(default_factory=dict)
    
    # Labels & Threat Context
    ground_truth_label: int = Field(default=0, description="0 = Benign, 1 = Malicious")
    attack_category: str = Field(default="Benign")
    mitre_technique_id: str = Field(default="T0000")

    @field_validator("layer_source")
    @classmethod
    def validate_layer(cls, v: str) -> str:
        valid_layers = {"network", "host", "application"}
        if v.lower() not in valid_layers:
            raise ValueError(f"layer_source must be one of {valid_layers}, got '{v}'")
        return v.lower()

    def to_flat_dict(self) -> Dict[str, Any]:
        """Convert to a flattened dictionary suitable for tabular and DuckDB storage."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        data["raw_features_json"] = json.dumps(self.raw_features)
        del data["raw_features"]
        return data


class ECSNormalizer:
    """Normalizes raw multi-layer event records into unified ECS format."""

    @staticmethod
    def normalize_network_flow(row: Dict[str, Any]) -> ECSLogRecord:
        """Normalize raw CIC-IDS2017 / UNSW-NB15 flow record."""
        ts = row.get("timestamp")
        if isinstance(ts, str):
            try:
                parsed_ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                parsed_ts = datetime.now(timezone.utc)
        elif isinstance(ts, datetime):
            parsed_ts = ts
        else:
            parsed_ts = datetime.now(timezone.utc)

        features = {
            "flow_duration": float(row.get("flow_duration", 0.0)),
            "tot_fwd_pkts": float(row.get("tot_fwd_pkts", 0.0)),
            "tot_bwd_pkts": float(row.get("tot_bwd_pkts", 0.0)),
            "totlen_fwd_pkts": float(row.get("totlen_fwd_pkts", 0.0)),
            "totlen_bwd_pkts": float(row.get("totlen_bwd_pkts", 0.0)),
            "fwd_pkt_len_mean": float(row.get("fwd_pkt_len_mean", 0.0)),
            "bwd_pkt_len_mean": float(row.get("bwd_pkt_len_mean", 0.0)),
            "flow_byts_s": float(row.get("flow_byts_s", 0.0)),
            "flow_pkts_s": float(row.get("flow_pkts_s", 0.0)),
            "syn_flag_cnt": int(row.get("syn_flag_cnt", 0)),
            "rst_flag_cnt": int(row.get("rst_flag_cnt", 0)),
            "psh_flag_cnt": int(row.get("psh_flag_cnt", 0)),
            "ack_flag_cnt": int(row.get("ack_flag_cnt", 0)),
            "urg_flag_cnt": int(row.get("urg_flag_cnt", 0)),
        }

        attack_cat = str(row.get("attack_category", "Benign"))
        label = int(row.get("ground_truth_label", 0 if attack_cat == "Benign" else 1))

        return ECSLogRecord(
            event_id=str(row.get("event_id", uuid.uuid4())),
            timestamp=parsed_ts,
            layer_source="network",
            src_ip=str(row.get("src_ip", "192.168.10.10")),
            dst_ip=str(row.get("dst_ip", "192.168.10.50")),
            src_port=int(row.get("src_port", 443)),
            dst_port=int(row.get("dst_port", 80)),
            protocol=str(row.get("protocol", "TCP")).upper(),
            host_id=str(row.get("host_id", f"host-{row.get('dst_ip', '192.168.10.50')}")),
            user_id=str(row.get("user_id", "system")),
            event_action="network_flow",
            raw_features=features,
            ground_truth_label=label,
            attack_category=attack_cat,
            mitre_technique_id=str(row.get("mitre_technique_id", "T0000"))
        )

    @staticmethod
    def normalize_host_event(row: Dict[str, Any]) -> ECSLogRecord:
        """Normalize Linux eBPF / BETH kernel process event."""
        ts = row.get("timestamp")
        parsed_ts = ts if isinstance(ts, datetime) else datetime.now(timezone.utc)

        features = {
            "args_num": int(row.get("args_num", 0)),
            "return_value": int(row.get("return_value", 0)),
            "event_id_code": int(row.get("event_id_code", 0)),
            "is_root_uid": 1 if int(row.get("user_id_num", 1000)) == 0 else 0,
            "child_spawn_velocity": float(row.get("child_spawn_velocity", 1.0)),
        }

        attack_cat = str(row.get("attack_category", "Benign"))
        label = int(row.get("ground_truth_label", 1 if (row.get("evil") == 1 or row.get("sus") == 1 or attack_cat != "Benign") else 0))

        return ECSLogRecord(
            event_id=str(row.get("event_id", uuid.uuid4())),
            timestamp=parsed_ts,
            layer_source="host",
            host_id=str(row.get("host_id", "host-node-01")),
            user_id=str(row.get("user_id", "user_12")),
            process_name=str(row.get("process_name", "bash")),
            process_id=int(row.get("process_id", 1001)),
            parent_process_id=int(row.get("parent_process_id", 1000)),
            event_action=str(row.get("event_action", "process_spawn")),
            raw_features=features,
            ground_truth_label=label,
            attack_category=attack_cat,
            mitre_technique_id=str(row.get("mitre_technique_id", "T1059"))
        )

    @staticmethod
    def normalize_application_event(row: Dict[str, Any]) -> ECSLogRecord:
        """Normalize CERT r4.2 / User behavioral logon or device event."""
        ts = row.get("timestamp")
        parsed_ts = ts if isinstance(ts, datetime) else datetime.now(timezone.utc)

        features = {
            "is_off_hours": int(row.get("is_off_hours", 0)),
            "failed_logon_burst": int(row.get("failed_logon_burst", 0)),
            "file_transfer_bytes": float(row.get("file_transfer_bytes", 0.0)),
            "usb_device_mounted": int(row.get("usb_device_mounted", 0)),
            "email_outbound_recipients": int(row.get("email_outbound_recipients", 0)),
        }

        attack_cat = str(row.get("attack_category", "Benign"))
        label = int(row.get("ground_truth_label", 0 if attack_cat == "Benign" else 1))

        return ECSLogRecord(
            event_id=str(row.get("event_id", uuid.uuid4())),
            timestamp=parsed_ts,
            layer_source="application",
            host_id=str(row.get("host_id", "host-node-01")),
            user_id=str(row.get("user_id", "user_12")),
            event_action=str(row.get("event_action", "user_logon")),
            raw_features=features,
            ground_truth_label=label,
            attack_category=attack_cat,
            mitre_technique_id=str(row.get("mitre_technique_id", "T1078"))
        )

