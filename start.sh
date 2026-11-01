#!/bin/bash
set -e

echo "[*] Initializing CyberVision Threat Detection & Explanation Engine..."

# Launch FastAPI Backend in background on port 8000
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 &

# Wait for backend initialization
sleep 3

# Launch Streamlit Workbench on Space Port 7860
python -m streamlit run dashboard/app.py \
    --server.port 7860 \
    --server.address 0.0.0.0 \
    --server.enableCORS false \
    --server.enableXsrfProtection false \
    --theme.base "dark" \
    --theme.primaryColor "#3b82f6" \
    --theme.backgroundColor "#0f172a" \
    --theme.secondaryBackgroundColor "#1e293b" \
    --theme.textColor "#f8fafc"

