"""
DuckDB Database and Parquet Storage Manager for CyberVision.
Provides high-performance analytical storage, querying, and export for unified ECS records.
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd

# Safe import of DuckDB with fallback if needed during package install
try:
    import duckdb
except ImportError:
    duckdb = None


class DuckDBManager:
    """Manages DuckDB embedded analytics database and Parquet exports for CyberVision."""

    def __init__(self, db_path: str = "data/processed/cybervision_ecs.duckdb"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema tables if duckdb is installed."""
        if duckdb is None:
            return
        
        conn = duckdb.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ecs_events (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP,
                layer_source VARCHAR,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                src_port INTEGER,
                dst_port INTEGER,
                protocol VARCHAR,
                host_id VARCHAR,
                user_id VARCHAR,
                process_name VARCHAR,
                process_id INTEGER,
                parent_process_id INTEGER,
                event_action VARCHAR,
                ground_truth_label INTEGER,
                attack_category VARCHAR,
                mitre_technique_id VARCHAR,
                raw_features_json VARCHAR
            );
        """)
        conn.close()

    def insert_records(self, records: List[Dict[str, Any]]):
        """Insert a batch of flattened ECS records into DuckDB."""
        if not records or duckdb is None:
            return
        
        df = pd.DataFrame(records)
        conn = duckdb.connect(self.db_path)
        table_cols = [c[0] for c in conn.execute("DESCRIBE ecs_events").fetchall()]

        # Ensure missing columns exist in df
        for col in table_cols:
            if col not in df.columns:
                if col == "is_synthetic":
                    df[col] = 1
                else:
                    df[col] = None

        # Reorder df columns to match table exactly
        aligned_df = df[table_cols]
        conn.register("batch_df", aligned_df)
        conn.execute("""
            INSERT INTO ecs_events
            SELECT * FROM batch_df;
        """)
        conn.close()

    def query(self, sql_query: str) -> pd.DataFrame:
        """Run an analytical SQL query against the ECS DuckDB storage."""
        if duckdb is None:
            raise RuntimeError("DuckDB package is not installed.")
        conn = duckdb.connect(self.db_path)
        result_df = conn.execute(sql_query).df()
        conn.close()
        return result_df

    def export_to_parquet(self, output_path: str = "data/processed/ecs_events.parquet"):
        """Export the unified DuckDB table to Apache Parquet format."""
        if duckdb is None:
            raise RuntimeError("DuckDB package is not installed.")
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        conn = duckdb.connect(self.db_path)
        conn.execute(f"COPY ecs_events TO '{output_path}' (FORMAT PARQUET);")
        conn.close()

    def get_summary_stats(self) -> Dict[str, Any]:
        """Return layer distribution and label counts."""
        if duckdb is None:
            return {}
        conn = duckdb.connect(self.db_path)
        total = conn.execute("SELECT count(*) FROM ecs_events").fetchone()[0]
        layer_dist = conn.execute("SELECT layer_source, count(*) as cnt FROM ecs_events GROUP BY layer_source").df().to_dict(orient="records")
        attack_dist = conn.execute("SELECT attack_category, count(*) as cnt FROM ecs_events GROUP BY attack_category").df().to_dict(orient="records")
        conn.close()
        return {
            "total_records": total,
            "layer_distribution": layer_dist,
            "attack_distribution": attack_dist
        }

