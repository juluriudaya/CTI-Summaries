"""Lab 15.2: shared collection -> collection-per-tenant migration.
Copies data; it never deletes the shared source collection.
"""
import argparse, hashlib, json, time
from datetime import datetime, timezone
from app.database import client

DB_NAME = "lab15_migration"
SOURCE = "tasks_shared"
TENANTS = ["tenant_acme", "tenant_globex", "tenant_innovate", "tenant_zenith", "tenant_nova"]

def checksum(docs):
    normalized = []
    for d in docs:
        d = dict(d)
        d.pop("_id", None)
        normalized.append(json.dumps(d, sort_keys=True, default=str))
    normalized.sort()
    return hashlib.sha256("\n".join(normalized).encode()).hexdigest()

def seed():
    col = client[DB_NAME][SOURCE]
    # This is an isolated lab-only source collection.
    col.delete_many({})
    now = datetime.now(timezone.utc)
    docs = []
    for tenant in TENANTS:
        for i in range(100):
            docs.append({
                "tenant_id": tenant,
                "task_no": i + 1,
                "title": f"{tenant}-task-{i+1:03d}",
                "status": ["open", "in_progress", "completed"][i % 3],
                "priority": ["low", "medium", "high"][i % 3],
                "created_at": now,
            })
    col.insert_many(docs)
    print(f"Seeded {len(docs)} documents for {len(TENANTS)} tenants.")

def target_name(tenant):
    return f"tasks_{tenant}"

def migrate(tenant, dry_run=False):
    source = client[DB_NAME][SOURCE]
    docs = list(source.find({"tenant_id": tenant}))
    if dry_run:
        print(f"DRY RUN: {len(docs)} documents would be copied to {target_name(tenant)}")
        return
    target = client[DB_NAME][target_name(tenant)]
    for doc in docs:
        target.replace_one({"_id": doc["_id"]}, doc, upsert=True)
    target.create_index([("created_at", -1)])
    target_docs = list(target.find({}))
    ok = len(docs) == len(target_docs) and checksum(docs) == checksum(target_docs)
    print(f"{tenant}: source={len(docs)}, target={len(target_docs)}, checksum={'PASS' if ok else 'FAIL'}")
    if not ok:
        raise RuntimeError(f"Migration validation failed for {tenant}")

def benchmark():
    db = client[DB_NAME]
    print("\nBenchmark (single local run; milliseconds; results are environment-dependent)")
    print(f"{'Tenant':18} {'Shared list':>14} {'Tenant collection':>19} {'Insert shared':>15} {'Insert tenant':>15}")
    for tenant in TENANTS:
        start = time.perf_counter()
        list(db[SOURCE].find({"tenant_id": tenant}))
        shared_ms = (time.perf_counter() - start) * 1000
        target = db[target_name(tenant)]
        start = time.perf_counter()
        list(target.find({}))
        tenant_ms = (time.perf_counter() - start) * 1000
        probe = {"tenant_id": tenant, "task_no": 1001, "title": "benchmark-probe", "status": "open", "priority": "low", "created_at": datetime.now(timezone.utc)}
        start = time.perf_counter()
        db[SOURCE].insert_one(probe)
        insert_shared = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        target.insert_one(dict(probe))
        insert_tenant = (time.perf_counter() - start) * 1000
        # Remove only the two uniquely titled benchmark probes.
        db[SOURCE].delete_one({"title": "benchmark-probe", "tenant_id": tenant})
        target.delete_one({"title": "benchmark-probe"})
        print(f"{tenant:18} {shared_ms:14.3f} {tenant_ms:19.3f} {insert_shared:15.3f} {insert_tenant:15.3f}")

    start = time.perf_counter()
    list(db[SOURCE].aggregate([{"$group": {"_id": "$tenant_id", "tasks": {"$sum": 1}}}]))
    shared_analytics = (time.perf_counter() - start) * 1000
    print(f"\nShared collection cross-tenant analytics: {shared_analytics:.3f} ms")
    print("Collection-per-tenant analytics requires querying/unioning the tenant collections.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", action="store_true", help="Seed isolated shared collection with 5 x 100 tasks")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--migrate-all", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    if args.seed:
        seed()
    if args.dry_run:
        for t in TENANTS: migrate(t, dry_run=True)
    if args.migrate_all:
        for t in TENANTS: migrate(t)
    if args.benchmark:
        benchmark()
    if not any([args.seed, args.dry_run, args.migrate_all, args.benchmark]):
        parser.print_help()

if __name__ == "__main__":
    main()
