from datetime import datetime, timezone
from contextlib import asynccontextmanager
from bson import ObjectId
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from .database import db, client, initialize_indexes
from .schemas import TaskCreate, TaskUpdate
from .security import verify_password, create_access_token, current_user, require_admin
from .rate_limit import enforce_rate_limit

@asynccontextmanager
async def lifespan(app: FastAPI):
    client.admin.command("ping")
    initialize_indexes()
    yield
    client.close()

app = FastAPI(title="Lab 15 Multi-Tenant Task API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

def serialize(doc):
    doc["id"] = str(doc.pop("_id"))
    return doc

@app.get("/health")
def health():
    client.admin.command("ping")
    return {"status": "ok", "database": "lab15_saas"}

@app.post("/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = db.users.find_one({"username": form.username})
    if not user or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"access_token": create_access_token(user), "token_type": "bearer"}

@app.post("/tasks/", status_code=status.HTTP_201_CREATED)
def create_task(task: TaskCreate, user: dict = Depends(current_user)):
    enforce_rate_limit(user["tenant_id"])
    now = datetime.now(timezone.utc)
    doc = {
        "tenant_id": user["tenant_id"],
        "owner_id": user["user_id"],
        "title": task.title,
        "description": task.description,
        "priority": task.priority,
        "status": "open",
        "created_at": now,
        "updated_at": now,
    }
    result = db.tasks.insert_one(doc)
    doc["_id"] = result.inserted_id
    return serialize(doc)

@app.get("/tasks/")
def list_tasks(user: dict = Depends(current_user)):
    enforce_rate_limit(user["tenant_id"])
    query = {"tenant_id": user["tenant_id"]}
    if user["role"] != "admin":
        query["owner_id"] = user["user_id"]
    return [serialize(t) for t in db.tasks.find(query).sort("created_at", -1)]

@app.get("/tasks/{task_id}")
def get_task(task_id: str, user: dict = Depends(current_user)):
    if not ObjectId.is_valid(task_id):
        raise HTTPException(status_code=400, detail="Invalid task id")
    query = {"_id": ObjectId(task_id), "tenant_id": user["tenant_id"]}
    if user["role"] != "admin":
        query["owner_id"] = user["user_id"]
    doc = db.tasks.find_one(query)
    if not doc:
        raise HTTPException(status_code=404, detail="Task not found")
    return serialize(doc)

@app.patch("/tasks/{task_id}")
def update_task(task_id: str, payload: TaskUpdate, user: dict = Depends(current_user)):
    if not ObjectId.is_valid(task_id):
        raise HTTPException(status_code=400, detail="Invalid task id")
    query = {"_id": ObjectId(task_id), "tenant_id": user["tenant_id"]}
    if user["role"] != "admin":
        query["owner_id"] = user["user_id"]
    updates = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No update fields supplied")
    updates["updated_at"] = datetime.now(timezone.utc)
    result = db.tasks.update_one(query, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"updated": True}

@app.delete("/tasks/{task_id}")
def delete_task(task_id: str, user: dict = Depends(current_user)):
    if not ObjectId.is_valid(task_id):
        raise HTTPException(status_code=400, detail="Invalid task id")
    query = {"_id": ObjectId(task_id), "tenant_id": user["tenant_id"]}
    if user["role"] != "admin":
        query["owner_id"] = user["user_id"]
    result = db.tasks.delete_one(query)
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"deleted": True}

@app.get("/admin/tenants/{tenant_id}/tasks")
def admin_list_tenant_tasks(tenant_id: str, admin: dict = Depends(require_admin)):
    # Admin is scoped to their own tenant; no cross-tenant super-admin behavior.
    if tenant_id != admin["tenant_id"]:
        raise HTTPException(status_code=403, detail="Cross-tenant access denied")
    return [serialize(t) for t in db.tasks.find({"tenant_id": tenant_id}).sort("created_at", -1)]
