"""
CyberVision Platform Launcher.
Provides an easy command-line interface to launch:
- FastAPI Backend Service (Port 8000)
- Streamlit SOC Workbench (Port 8501)
- Master Research Benchmarks
"""

import sys
import subprocess
import argparse


def launch_api():
    print("[*] Launching CyberVision FastAPI Backend on http://127.0.0.1:8000 ...")
    subprocess.run([sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"])


def launch_dashboard():
    print("[*] Launching CyberVision SOC Analyst Dashboard on http://localhost:8501 ...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "dashboard/app.py", "--server.port", "8501"])


def run_benchmarks():
    print("[*] Running CyberVision Master Research Benchmarks...")
    subprocess.run([sys.executable, "-m", "src.evaluation.run_benchmarks"])


def main():
    parser = argparse.ArgumentParser(description="CyberVision Platform Runner")
    parser.add_argument("--mode", choices=["api", "dashboard", "benchmarks", "all"], default="dashboard",
                        help="Component to launch ('api', 'dashboard', 'benchmarks')")
    args = parser.parse_args()

    if args.mode == "api":
        launch_api()
    elif args.mode == "dashboard":
        launch_dashboard()
    elif args.mode == "benchmarks":
        run_benchmarks()
    elif args.mode == "all":
        print("[*] Starting API and Dashboard...")
        api_proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000"])
        launch_dashboard()
        api_proc.terminate()


if __name__ == "__main__":
    main()

