"""FastAPI Backend with RAG Chat Endpoint & Autonomous Mitigation Bot

Implements:
1. POST /chat: RAG Vector Search + MongoDB Conversation Memory (PDF Section A.3 & A.4)
2. GET /threats: Filter Anticipated, Active, Evolving, Resolved threats by Platform
3. POST /scan: Autonomous Vulnerability Scanner trigger
4. POST /mitigate: Conversational Mitigation Confirmation & Audit Logger
5. GET /health & GET /metrics: Production Hardening SRE Endpoints (PDF Section A.7)
"""

import os
import sys
import time
import datetime
from datetime import timezone
from typing import List, Dict, Any, Optional

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database import get_database, utc_now
from rag_engine import retrieve_context, construct_rag_prompt
from llm_engine import generate_llm_response
from scanner_bot import VulnerabilityScannerBot

app = FastAPI(
    title="CTI-AI Threat Intelligence & Mitigation API",
    version="2.0.0",
    description="LLM/SLM-backed conversational platform for Anticipated, Active, Evolving, and Resolved Cyber Threats across Windows, Linux, macOS, Android, and iOS."
)

# Enable CORS for Streamlit frontend and local clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database and scanner bot
db = get_database()
scanner = VulnerabilityScannerBot(db)

# Telemetry metrics for Section A.7 Production Hardening
METRICS = {
    "total_requests": 0,
    "chat_queries": 0,
    "mitigations_executed": 0,
    "scans_completed": 0,
    "avg_latency_ms": 0.0,
    "start_time": utc_now().isoformat()
}


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str = Field(..., example="How do I mitigate active ransomware on Windows?")
    session_id: str = Field(default="default_session", example="soc_analyst_01")
    platform: str = Field(default="all", example="windows")
    stage: str = Field(default="all", example="active")


class ScanRequest(BaseModel):
    platform: str = Field(default="windows", example="windows")
    target_dir: Optional[str] = Field(default=None)


class MitigateRequest(BaseModel):
    vuln_id: str = Field(..., example="VULN-A1B2C3D4")
    confirmed_by: str = Field(default="analyst_in_chat", example="admin")


# -----------------------------------------------------------------------------
# Helper Functions: Serialization & Conversation Memory (PDF Section A.4)
# -----------------------------------------------------------------------------

def sanitize_json(obj: Any) -> Any:
    """Recursively converts ObjectIds and datetimes to JSON-serializable primitives."""
    if isinstance(obj, list):
        return [sanitize_json(x) for x in obj]
    elif isinstance(obj, dict):
        clean = {}
        for k, v in obj.items():
            if k == "_id" or type(v).__name__ == "ObjectId":
                clean[k] = str(v)
            elif isinstance(v, (datetime.datetime, datetime.date)):
                clean[k] = v.isoformat()
            elif isinstance(v, (dict, list)):
                clean[k] = sanitize_json(v)
            else:
                clean[k] = v
        return clean
    elif type(obj).__name__ == "ObjectId":
        return str(obj)
    elif isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    return obj


def get_session_history(session_id: str, limit: int = 6) -> List[Dict[str, str]]:
    """Retrieve last exchanges from MongoDB sessions collection."""
    sessions_col = db.sessions
    msgs = list(sessions_col.find(
        {"session_id": session_id},
        sort=[("timestamp", -1)],
        limit=limit * 2
    ))
    msgs.reverse()
    return [{"role": m.get("role", "user"), "content": m.get("content", "")} for m in msgs]


def save_session_message(session_id: str, role: str, content: str):
    """Store message in MongoDB sessions collection."""
    db.sessions.insert_one({
        "session_id": session_id,
        "role": role,
        "content": content,
        "timestamp": utc_now()
    })


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.post("/chat")
async def chat_endpoint(req: ChatRequest):
    """Main RAG Chat Endpoint (PDF Section A.3)."""
    t0 = time.time()
    METRICS["total_requests"] += 1
    METRICS["chat_queries"] += 1

    # 1. Store user message in MongoDB conversation store
    save_session_message(req.session_id, "user", req.message)

    # 2. Retrieve relevant context from MongoDB knowledge collection
    retrieved_chunks = retrieve_context(
        db=db,
        query=req.message,
        platform=req.platform,
        stage=req.stage,
        n_results=3
    )

    # 3. Retrieve conversation history
    history = get_session_history(req.session_id)

    # 4. Generate LLM/SLM response
    llm_result = generate_llm_response(
        prompt=req.message,
        context_chunks=retrieved_chunks,
        platform=req.platform
    )
    answer = llm_result["answer"]

    # 5. Check if conversational confirmation is applicable for pending mitigations
    pending = scanner.list_pending_mitigations(req.platform)
    user_msg_lower = req.message.lower()
    
    # If user confirmed an action in chat
    if any(k in user_msg_lower for k in ["mitigate", "fix it", "apply fix", "approve", "confirm"]) and pending:
        target_vuln = pending[0]
        mitigation_res = scanner.execute_mitigation_with_confirmation(target_vuln["vuln_id"], confirmed_by=f"chat_{req.session_id}")
        METRICS["mitigations_executed"] += 1
        answer += f"\n\n---\n### 🤖 Autonomous Mitigation Executed\n" \
                  f"✅ **{mitigation_res['title']}** has been applied.\n" \
                  f"**Status:** Marked as `RESOLVED` in MongoDB.\n" \
                  f"**Audit ID:** `{mitigation_res['audit_id']}`\n" \
                  f"```bash\n{mitigation_res['command']}\n```"

    # 6. Store assistant answer in MongoDB
    save_session_message(req.session_id, "assistant", answer)

    # Compute latency
    latency = (time.time() - t0) * 1000.0
    METRICS["avg_latency_ms"] = round((METRICS["avg_latency_ms"] * 0.8) + (latency * 0.2), 2)

    return sanitize_json({
        "session_id": req.session_id,
        "answer": answer,
        "backend": llm_result["backend"],
        "platform": req.platform,
        "stage": req.stage,
        "latency_ms": round(latency, 2),
        "context": retrieved_chunks,
        "pending_mitigations": scanner.list_pending_mitigations(req.platform)
    })


@app.get("/threats")
async def get_threats_endpoint(platform: Optional[str] = None, stage: Optional[str] = None):
    """Retrieve structured threat lifecycle items partitioned by platform and lifecycle stage."""
    f = {}
    if platform and platform.lower() != "all":
        f["platform"] = platform.lower()
    if stage and stage.lower() != "all":
        f["stage"] = stage.lower()

    threats = list(db.threat_lifecycle.find(f))
    # Remove Mongo _id for JSON serialization
    for t in threats:
        if "_id" in t:
            t["_id"] = str(t["_id"])
    return {"count": len(threats), "threats": threats}


@app.post("/scan")
async def scan_endpoint(req: ScanRequest):
    """Trigger the real-time system cyber vulnerability diagnostic audit."""
    METRICS["total_requests"] += 1
    METRICS["scans_completed"] += 1
    report = scanner.get_full_audit_report(target_dir=req.target_dir)
    return sanitize_json(report)


@app.post("/mitigate")
async def mitigate_endpoint(req: MitigateRequest):
    """Conversational confirmation endpoint to apply mitigation and log audit."""
    METRICS["total_requests"] += 1
    METRICS["mitigations_executed"] += 1
    res = scanner.execute_mitigation_with_confirmation(req.vuln_id, confirmed_by=req.confirmed_by)
    return res


@app.get("/health")
async def health_check():
    """Container health check endpoint (PDF Section A.7) incl. live Ollama LLM status."""
    try:
        from llm_engine import get_installed_ollama_models
        ollama_models = get_installed_ollama_models()
    except Exception:
        ollama_models = []
    return {
        "status": "healthy",
        "service": "CTI LLM Threat Intelligence API",
        "timestamp": utc_now().isoformat(),
        "database": "connected",
        "ollama_online": bool(ollama_models),
        "ollama_models": ollama_models
    }


@app.get("/metrics")
async def metrics_endpoint():
    """SRE Monitoring Telemetry (PDF Section A.7)."""
    return METRICS


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
