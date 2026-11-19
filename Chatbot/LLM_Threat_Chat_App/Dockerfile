# =============================================================================
# CTI CHAT BOT — UNIFIED ENTERPRISE DOCKERFILE
# Packages FastAPI Backend (Port 8005) + Streamlit UI (Port 8503) + ML Weights
# =============================================================================
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and pre-trained weights
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Default environment configuration
ENV PYTHONUNBUFFERED=1 \
    MONGO_URI=mongodb://host.docker.internal:27017 \
    MONGO_DB=llm_threat_intel \
    BACKEND_URL=http://localhost:8005 \
    OLLAMA_BASE_URL=http://host.docker.internal:11434

# Expose Streamlit UI (8503) and FastAPI Backend (8005)
EXPOSE 8503 8005

# Container healthcheck
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8005/health || exit 1

ENTRYPOINT ["/bin/bash", "/app/start.sh"]
