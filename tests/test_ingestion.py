"""
Test Suite for CyberVision Ingestion, ECS Normalization, and DuckDB Storage.
"""

import pytest
import os
from src.ingestion.ecs_normalizer import ECSNormalizer
from src.ingestion.db_manager import DuckDBManager


def test_ecs_normalizer():
    normalizer = ECSNormalizer()

    # Network normalization
    raw_net = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "flow_duration": 5000,
        "flow_bytes_s": 12000.0,
        "Label": "BENIGN"
    }
    rec_net = normalizer.normalize_network_flow(raw_net)
    assert rec_net.layer_source == "network"
    assert rec_net.ground_truth_label == 0
    assert rec_net.dst_port == 443

    # Host normalization
    raw_host = {
        "host_id": "host-test-01",
        "user_id": "alice",
        "process_name": "sudo",
        "process_id": 9999,
        "parent_process_id": 1,
        "event_action": "privilege_escalation",
        "label": 1,
        "attack_category": "Kernel_PrivEsc_Setuid"
    }
    rec_host = normalizer.normalize_host_event(raw_host)
    assert rec_host.layer_source == "host"
    assert rec_host.ground_truth_label == 1
    assert rec_host.host_id == "host-test-01"


def test_duckdb_manager():
    test_db_path = "data/cache/test_duckdb.duckdb"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    mgr = DuckDBManager(db_path=test_db_path)
    sample_records = [
        {
            "event_id": "ev-001",
            "timestamp": "2026-11-01T12:00:00",
            "layer_source": "network",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 8080,
            "dst_port": 80,
            "protocol": "TCP",
            "host_id": "host-1",
            "user_id": "system",
            "process_name": "httpd",
            "process_id": 100,
            "parent_process_id": 1,
            "event_action": "flow_end",
            "ground_truth_label": 0,
            "attack_category": "Benign",
            "mitre_technique_id": "N/A",
            "raw_features_json": "{}",
            "is_synthetic": 0
        }
    ]
    mgr.insert_records(sample_records)
    res = mgr.query("SELECT count(*) as cnt FROM ecs_events WHERE event_id = 'ev-001'")
    assert res.iloc[0]["cnt"] == 1

    stats = mgr.get_summary_stats()
    assert stats["total_records"] == 1

    if os.path.exists(test_db_path):
        os.remove(test_db_path)


def test_empty_database_handling():
    empty_db_path = "data/cache/empty_test_db.duckdb"
    if os.path.exists(empty_db_path):
        os.remove(empty_db_path)

    mgr = DuckDBManager(db_path=empty_db_path)
    res = mgr.query("SELECT * FROM ecs_events WHERE 1=0")
    assert res.empty
    stats = mgr.get_summary_stats()
    assert stats["total_records"] == 0

    if os.path.exists(empty_db_path):
        os.remove(empty_db_path)
