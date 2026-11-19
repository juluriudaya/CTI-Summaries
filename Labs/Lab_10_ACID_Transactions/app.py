import json
import os, time, hashlib, uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import PyMongoError, OperationFailure

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27217/?replicaSet=rs0&directConnection=true&retryWrites=true&w=majority&serverSelectionTimeoutMS=8000")
DB_NAME = os.getenv("DB_NAME", "lab10_app")
FREE_TRIALS = int(os.getenv("FREE_TRIALS", "3"))
BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000, connectTimeoutMS=5000)
db = client[DB_NAME]
users = db["users"]
usage = db["usage"]
transfers = db["bank_transfers"]
accounts = db["bank_accounts"]
inventory = db["inventory"]
orders = db["inventory_orders"]
idempotency = db["idempotency"]
app = FastAPI(title="Lab 10 — ACID Transactions & Concurrency", version="1.0.0")

def utcnow():
    return datetime.now(timezone.utc)

@app.on_event("startup")
def setup_indexes():
    # Unique keys prevent duplicate users, orders, and idempotency keys.
    users.create_index("email", unique=True)
    accounts.create_index("account_id", unique=True)
    transfers.create_index("transfer_id", unique=True)
    inventory.create_index("product_id", unique=True)
    orders.create_index("order_id", unique=True)
    idempotency.create_index("key", unique=True)
    try:
        client.admin.command("ping")
    except Exception as exc:
        print("MongoDB not ready yet:", exc)

class RegisterIn(BaseModel):
    user_id: str = Field(min_length=2, max_length=80)
    email: str
class BankAccountIn(BaseModel):
    account_id: str
    owner: str
    balance: float = Field(ge=0)
class TransferIn(BaseModel):
    transfer_id: str
    from_account: str
    to_account: str
    amount: float = Field(gt=0, le=100000000)
    description: str = "Bank transfer"
class PlanIn(BaseModel):
    user_id: str
    plan: str
class ReserveIn(BaseModel):
    order_id: str
    user_id: str
    product_id: str
    qty: int = Field(gt=0, le=10000)

def require_user(user_id):
    u = users.find_one({"user_id": user_id})
    if not u:
        raise HTTPException(404, "User not found; register first.")
    return u

def subscription_active(u):
    return u.get("subscription_status") == "active" and u.get("subscription_until") and u["subscription_until"] > utcnow()

def consume_trial_or_require_subscription(user_id, action_id):
    """Atomic one-time action ledger. Unique action_id makes retries idempotent."""
    require_user(user_id)
    try:
        # One usage record per action, so a repeated request with the same ID cannot consume another trial.
        usage.insert_one({"action_id": action_id, "user_id": user_id, "created_at": utcnow()})
    except Exception:
        existing = usage.find_one({"action_id": action_id})
        if existing and existing.get("user_id") == user_id:
            return "already_counted"
        raise HTTPException(409, "Duplicate action ID.")
    u = users.find_one_and_update(
        {"user_id": user_id, "$expr": {"$lt": [{"$ifNull": ["$trial_used", 0]}, FREE_TRIALS]}},
        {"$inc": {"trial_used": 1}},
        return_document=ReturnDocument.AFTER
    )
    if u:
        return f"free_trial_{u.get('trial_used')}_of_{FREE_TRIALS}"
    # Roll back usage marker if user is subscribed; otherwise reject. Subscription checks happen before counting.
    usage.delete_one({"action_id": action_id, "user_id": user_id})
    u = require_user(user_id)
    if subscription_active(u):
        return "subscription"
    raise HTTPException(402, "Free trials used. Activate subscription to continue via POST /users/subscribe.")

@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html><head><title>Lab 10 ACID Demo</title>
    <style>body{font:16px Arial;max-width:900px;margin:40px auto;padding:0 20px}code{background:#eee;padding:3px}li{margin:8px 0}</style></head><body>
    <h1>Lab 10 — ACID Transaction & Subscription Demo</h1>
    <p>API status: <a href="/health">/health</a> | API docs: <a href="/docs">/docs</a></p>
    <h2>Features</h2><ul><li>ACID bank transfer transaction with insufficient-balance rollback</li>
    <li>Three free protected actions per user, followed by direct subscription activation</li>
    <li>Inventory reservation transaction and contention-safe stock decrement</li>
    <li>Idempotency keys and unique indexes prevent duplicate processing</li>
    <li>MongoDB replica set supports primary election if a primary container fails</li></ul>
    <p>This is a teaching demo for multi-document ACID transactions and snapshot isolation on MongoDB.</p></body></html>"""

@app.get("/health")
def health():
    try:
        hello = client.admin.command("hello")
        return {"ok": True, "replica_set": hello.get("setName"), "primary": hello.get("primary"), "isWritablePrimary": hello.get("isWritablePrimary")}
    except Exception as e:
        raise HTTPException(503, f"MongoDB unavailable: {e}")

@app.get("/replica-status")
def replica_status():
    try:
        s = client.admin.command("replSetGetStatus")
        return {"set": s.get("set"), "members": [{"name": m.get("name"), "state": m.get("stateStr"), "health": m.get("health")} for m in s.get("members", [])]}
    except Exception as e:
        raise HTTPException(503, str(e))

@app.post("/users/register")
def register(x: RegisterIn):
    doc = {"user_id": x.user_id, "email": x.email.lower().strip(), "trial_used": 0, "subscription_status": "inactive", "subscription_until": None, "created_at": utcnow()}
    try:
        users.insert_one(doc)
    except Exception:
        raise HTTPException(409, "User ID or email already exists.")
    return {"created": True, "user_id": x.user_id, "free_trials": FREE_TRIALS}

@app.get("/users/{user_id}")
def user_info(user_id: str):
    u = require_user(user_id)
    return {"user_id": user_id, "email": u["email"], "trial_used": u.get("trial_used", 0), "free_trials": FREE_TRIALS, "trials_remaining": max(0, FREE_TRIALS-u.get("trial_used",0)), "subscription_status": u.get("subscription_status"), "subscription_until": u.get("subscription_until")}

@app.post("/bank/accounts")
def create_account(x: BankAccountIn):
    try:
        accounts.insert_one({"account_id": x.account_id, "owner": x.owner, "balance": round(x.balance, 2), "version": 0, "created_at": utcnow()})
    except Exception:
        raise HTTPException(409, "Account ID already exists.")
    return {"created": True, "account_id": x.account_id}

@app.get("/bank/accounts")
def list_accounts():
    return list(accounts.find({}, {"_id": 0}))

@app.post("/bank/transfer")
def bank_transfer(x: TransferIn, idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key")):
    if x.from_account == x.to_account:
        raise HTTPException(400, "Source and destination accounts must differ.")
    key = idempotency_key or x.transfer_id
    existing = transfers.find_one({"transfer_id": x.transfer_id})
    if existing:
        return {"status": "already_processed", "transfer_id": x.transfer_id}

    def transfer_transaction(session):
        prior = transfers.find_one({"transfer_id": x.transfer_id}, session=session)
        if prior:
            return {"status": "already_processed", "transfer_id": x.transfer_id}
        amount = round(x.amount, 2)
        debit = accounts.update_one(
            {"account_id": x.from_account, "balance": {"$gte": amount}},
            {"$inc": {"balance": -amount, "version": 1}}, session=session)
        if debit.matched_count != 1:
            src = accounts.find_one({"account_id": x.from_account}, session=session)
            if not src:
                raise HTTPException(404, "Source account not found.")
            raise HTTPException(422, "Insufficient balance.")
        credit = accounts.update_one(
            {"account_id": x.to_account},
            {"$inc": {"balance": amount, "version": 1}}, session=session)
        if credit.matched_count != 1:
            raise HTTPException(404, "Destination account not found; transaction rolled back.")
        transfers.insert_one(
            {"transfer_id": x.transfer_id, "from_account": x.from_account,
             "to_account": x.to_account, "amount": amount,
             "description": x.description, "status": "committed",
             "created_at": utcnow()},
            session=session)
        return {"status": "committed", "transfer_id": x.transfer_id, "amount": amount}

    try:
        with client.start_session() as session:
            return session.with_transaction(transfer_transaction)
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(503, f"Transaction failed after MongoDB retries: {e}")

@app.post("/protected/action")
def protected_action(user_id: str, action_id: str):
    result = consume_trial_or_require_subscription(user_id, action_id)
    return {"status": result, "user_id": user_id, "action_id": action_id}  
@app.post("/users/subscribe")
def subscribe_user(x: PlanIn):
    u = require_user(x.user_id)
    if x.plan not in ("monthly", "yearly"):
        raise HTTPException(422, "plan must be monthly or yearly")
    now = utcnow()
    duration = timedelta(days=30) if x.plan == "monthly" else timedelta(days=365)
    users.update_one(
        {"user_id": x.user_id},
        {"$set": {
            "subscription_status": "active",
            "subscription_plan": x.plan,
            "subscription_until": now + duration
        }}
    )
    return {
        "status": "active",
        "user_id": x.user_id,
        "plan": x.plan,
        "subscription_until": (now + duration).isoformat()
    }

@app.post("/inventory/seed")
def seed_inventory():
    inventory.update_one({"product_id":"LAPTOP"}, {"$setOnInsert":{"product_id":"LAPTOP","name":"Laptop","stock":5,"price":999.0,"version":0}}, upsert=True)
    return {"seeded": True, "product": inventory.find_one({"product_id":"LAPTOP"},{"_id":0})}

@app.get("/inventory")
def get_inventory():
    return list(inventory.find({}, {"_id":0}))

@app.post("/inventory/reserve")
def reserve_inventory(x: ReserveIn):
    existing = orders.find_one({"order_id":x.order_id})
    if existing:
        return {"status":"already_reserved","order_id":x.order_id}
    for attempt in range(5):
        session = client.start_session()
        try:
            with session.start_transaction():
                if orders.find_one({"order_id":x.order_id}, session=session):
                    return {"status":"already_reserved","order_id":x.order_id}
                item = inventory.find_one({"product_id":x.product_id}, session=session)
                if not item:
                    raise HTTPException(404, "Product not found.")
                result = inventory.update_one({"product_id":x.product_id,"stock":{"$gte":x.qty}}, {"$inc":{"stock":-x.qty,"version":1}}, session=session)
                if result.matched_count != 1:
                    raise HTTPException(409, "Insufficient stock.")
                orders.insert_one({"order_id":x.order_id,"user_id":x.user_id,"product_id":x.product_id,"qty":x.qty,"status":"reserved","created_at":utcnow()}, session=session)
            return {"status":"reserved","order_id":x.order_id}
        except HTTPException:
            raise
        except PyMongoError as e:
            labels = getattr(e, "_error_labels", set())
            if attempt < 4 and ("TransientTransactionError" in labels or isinstance(e, OperationFailure)):
                time.sleep(0.1 * (2**attempt))
                continue
            raise HTTPException(503, f"Reservation failed after retries: {e}")
        finally:
            session.end_session()
    raise HTTPException(503, "Reservation retry limit reached.")

@app.get("/transactions")
def transaction_history():
    return {
        "bank_transfers": list(transfers.find({}, {"_id":0}).sort("created_at",-1).limit(100)),
        "inventory_orders": list(orders.find({}, {"_id":0}).sort("created_at",-1).limit(100))
    }
