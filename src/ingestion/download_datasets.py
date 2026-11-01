"""
Automated Dataset Acquisition & Guidance Script for CyberVision.
Handles downloading, verifying, and preparing CIC-IDS2017, UNSW-NB15, BETH, and CERT r4.2 datasets.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any

RAW_DIR = Path("data/raw")

DATASET_INVENTORY = {
    "cic_ids2017": {
        "layer": "Layer 1 (Network Traffic)",
        "expected_files": ["cicids2017.parquet", "CIC-IDS2017_sample.csv"],
        "hf_source": "lacg030175/CICIDS2017",
        "kaggle_mirror": "https://www.kaggle.com/datasets/raihansultan/cicids2017",
        "official_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "description": "Stratified network flows covering DoS, DDoS, Brute Force, Web Attacks, and Botnets."
    },
    "unsw_nb15": {
        "layer": "Layer 1B (Modern Network Benchmark)",
        "expected_files": ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"],
        "kaggle_mirror": "https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15",
        "official_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "description": "UNSW-NB15 training & testing flow sets covering Fuzzers, Backdoors, Worms, and Exploits."
    },
    "beth": {
        "layer": "Layer 2 (Host & Kernel Process Telemetry)",
        "expected_files": ["beth_honeypot.csv", "b_events.csv"],
        "kaggle_mirror": "https://www.kaggle.com/datasets/katehighnam/beth-dataset",
        "github_mirror": "https://github.com/jinxmirror13/BETH_Dataset_Analysis",
        "description": "Linux kernel eBPF process telemetry with process IDs, parent PIDs, return values, and evil/sus labels."
    },
    "cert_r4_2": {
        "layer": "Layer 3 (User & Application Behavioral UEBA)",
        "expected_files": ["cert_r4.2.parquet", "logon.csv", "device.csv", "file.csv"],
        "hf_source": "nguynn/cert-insider-threat-datasets",
        "kaggle_mirror": "https://www.kaggle.com/datasets/andrihjonior/cert-insider-threat-dataset-r4-2",
        "description": "Multi-source enterprise insider threat logs: after-hours logons, USB flash drives, file exfiltrations."
    }
}


def check_local_datasets() -> Dict[str, bool]:
    """Check which raw datasets are present in data/raw/."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    status = {}
    for key, meta in DATASET_INVENTORY.items():
        found = False
        for expected in meta["expected_files"]:
            if (RAW_DIR / expected).exists():
                found = True
                break
        status[key] = found
    return status


def print_dataset_instructions():
    """Print instructions for any missing benchmark dataset."""
    status = check_local_datasets()
    print("=" * 80)
    print("CYBERVISION MULTI-LAYER DATASET INVENTORY STATUS")
    print("=" * 80)
    for key, present in status.items():
        meta = DATASET_INVENTORY[key]
        mark = "[FOUND]" if present else "[MISSING / FALLBACK]"
        print(f"{mark} {meta['layer']} -> {key.upper()}")
        print(f"       Expected in data/raw/: {', '.join(meta['expected_files'])}")
        if not present:
            print(f"       Download from Kaggle: {meta['kaggle_mirror']}")
            if "hf_source" in meta:
                print(f"       HuggingFace Mirror: https://huggingface.co/datasets/{meta['hf_source']}")
    print("=" * 80)


def try_download_from_huggingface():
    """Attempt automated download of HuggingFace mirrors if datasets library is available."""
    try:
        from datasets import load_dataset
        print("[*] Attempting HuggingFace auto-fetch for sample splits...")
        
        # Layer 1 test fetch
        cic_path = RAW_DIR / "cicids2017.parquet"
        if not cic_path.exists():
            print("    Fetching CIC-IDS2017 subset from HuggingFace...")
            try:
                ds = load_dataset("lacg030175/CICIDS2017", split="train[:5000]")
                df = ds.to_pandas()
                df.to_parquet(cic_path)
                print(f"    Saved {len(df)} sample rows to {cic_path}")
            except Exception as e:
                print(f"    Notice: HuggingFace fetch for CIC-IDS2017 skipped ({e}). Using synthetic generator.")
    except ImportError:
        print("[*] 'datasets' library not available for direct HuggingFace pull. Using fallback generator.")


if __name__ == "__main__":
    print_dataset_instructions()
    try_download_from_huggingface()

