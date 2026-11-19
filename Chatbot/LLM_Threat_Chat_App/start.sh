#!/bin/bash
set -e

echo "=============================================================================="
echo "  🛡️ CTI CHAT BOT — DOCKER UNIFIED CONTAINER"
echo "=============================================================================="
echo "Target MongoDB: ${MONGO_URI:-mongodb://host.docker.internal:27017}"
echo "Backend Port:   8005"
echo "Frontend Port:  8503"
echo "=============================================================================="

# 1. Start FastAPI Backend on port 8005 in background
echo "[1/2] Starting FastAPI CTI-AI Backend on port 8005..."
python -m uvicorn main:app --host 0.0.0.0 --port 8005 --app-dir /app/backend &

# Wait for backend to be ready
sleep 2

# 2. Start Streamlit CTI Chat Bot on port 8503 in foreground
echo "[2/2] Starting Streamlit CTI Chat Bot UI on port 8503..."
exec python -m streamlit run /app/frontend/chat_app.py \
    --server.port 8503 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false
