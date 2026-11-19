"""Small direct database demo proving tenant-scoped CRUD and indexes."""
from bson import ObjectId
from app.database import db, initialize_indexes
from datetime import datetime, timezone

def main():
    initialize_indexes()
    col = db.tasks
    # Only clear documents belonging to these lab demo tenants.
    col.delete_many({"tenant_id": {"$in": ["tenant-demo-acme", "tenant-demo-globex"]}})
    now = datetime.now(timezone.utc)
    inserted = col.insert_one({
        "tenant_id": "tenant-demo-acme", "owner_id": "demo-user-1",
        "title": "Demonstrate tenant isolation", "description": "Lab 15.1 sample",
        "priority": "high", "status": "open", "created_at": now, "updated_at": now
    })
    task_id = inserted.inserted_id
    print("Acme sees:", col.count_documents({"tenant_id": "tenant-demo-acme"}), "demo task(s)")
    print("Globex sees:", col.count_documents({"tenant_id": "tenant-demo-globex"}), "demo task(s)")
    blocked = col.update_one(
        {"_id": task_id, "tenant_id": "tenant-demo-globex"},
        {"$set": {"status": "deleted"}}
    )
    print("Cross-tenant update blocked:", blocked.matched_count == 0)
    print("Indexes:", col.index_information())

if __name__ == "__main__":
    main()
