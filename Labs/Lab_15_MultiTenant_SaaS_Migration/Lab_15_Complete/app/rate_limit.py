import os
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from pymongo import ReturnDocument
from dotenv import load_dotenv
from .database import db

load_dotenv()
LIMIT = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

def enforce_rate_limit(tenant_id: str):
    """Atomic fixed-window counter, scoped per tenant, with TTL cleanup."""
    now = datetime.now(timezone.utc)
    window_start = now.replace(second=(now.second // WINDOW) * WINDOW, microsecond=0)
    # Use a stable per-tenant window key; increment is atomic.
    key = f"{tenant_id}:{int(window_start.timestamp())}"
    expires = window_start + timedelta(seconds=WINDOW * 2)
    doc = db.rate_limits.find_one_and_update(
        {"_id": key},
        {
            "$inc": {"count": 1},
            "$setOnInsert": {
                "tenant_id": tenant_id,
                "window_start": window_start,
                "expires_at": expires,
            },
        },
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    if doc["count"] > LIMIT:
        raise HTTPException(status_code=429, detail="Tenant rate limit exceeded")
