"""
Lab 14.2 - Automated Backup and Restore Verification

IMPORTANT:
- Uses only the dedicated lab14_backup_restore database and backup folder.
- Restore uses --drop only for the dedicated test collection namespace.
- Hourly scheduler and 7-day retention are included.
- mongodump/mongorestore must be installed and available on PATH.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from pymongo import MongoClient

DB_NAME = "lab14_backup_restore"
COLLECTION = "backup_test"
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_BACKUP_ROOT = BASE_DIR / "backups"
RETENTION_DAYS = 7


def tools_available() -> bool:
    return shutil.which("mongodump") is not None and shutil.which("mongorestore") is not None


def run_command(command: list[str]) -> float:
    """Run a MongoDB Database Tools command and return elapsed seconds."""
    print("Running:", " ".join(command[:2]), "...")  # avoids printing full URI credentials
    start = time.perf_counter()
    result = subprocess.run(command, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed (exit {result.returncode}): {result.stderr[-1500:]}"
        )
    return elapsed


def checksum_collection(collection) -> str:
    rows = [
        json.dumps(doc, sort_keys=True, default=str)
        for doc in collection.find({}, {"_id": 0}).sort("_id", 1)
    ]
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def make_backup(uri: str, backup_root: Path) -> tuple[Path, float]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = backup_root / timestamp
    backup_dir.mkdir(parents=True, exist_ok=False)

    elapsed = run_command([
        "mongodump",
        f"--uri={uri}",
        f"--db={DB_NAME}",
        f"--collection={COLLECTION}",
        f"--out={str(backup_dir)}",
    ])
    print(f"Backup saved to: {backup_dir} ({elapsed:.2f} seconds)")
    return backup_dir, elapsed


def apply_retention(backup_root: Path, retention_days: int = RETENTION_DAYS) -> None:
    """Delete only timestamped child folders within this lab's backup root."""
    if not backup_root.exists():
        return
    cutoff = datetime.now().timestamp() - retention_days * 24 * 60 * 60
    for child in backup_root.iterdir():
        if child.is_dir() and child.name[:8].isdigit():
            if child.stat().st_mtime < cutoff:
                shutil.rmtree(child)
                print(f"Removed expired lab backup: {child.name}")


def seed_test_data(collection, count: int) -> tuple[int, str]:
    collection.delete_many({})
    batch_size = 5000
    for start in range(0, count, batch_size):
        docs = [
            {
                "sequence": i,
                "record_id": f"LAB14-{i:06d}",
                "value": round(i * 1.2345, 4),
                "verified": True,
                "created_at": datetime.utcnow(),
            }
            for i in range(start, min(start + batch_size, count))
        ]
        collection.insert_many(docs)
    return collection.count_documents({}), checksum_collection(collection)


def verify_restore(collection, expected_count: int, expected_checksum: str) -> bool:
    actual_count = collection.count_documents({})
    actual_checksum = checksum_collection(collection)
    count_ok = actual_count == expected_count
    checksum_ok = actual_checksum == expected_checksum
    print(f"Document count: expected={expected_count}, restored={actual_count} -> {'PASS' if count_ok else 'FAIL'}")
    print(f"Content checksum: {'PASS' if checksum_ok else 'FAIL'}")
    return count_ok and checksum_ok


def restore_backup(uri: str, backup_dir: Path) -> float:
    dump_db_dir = backup_dir / DB_NAME
    if not dump_db_dir.exists():
        raise FileNotFoundError(f"Database dump folder not found: {dump_db_dir}")
    # --drop is restricted to this lab's one collection namespace.
    return run_command([
        "mongorestore",
        f"--uri={uri}",
        f"--nsInclude={DB_NAME}.{COLLECTION}",
        "--drop",
        str(backup_dir),
    ])


def run_restore_verification(uri: str, backup_root: Path, count: int) -> None:
    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
    try:
        client.admin.command("ping")
        collection = client[DB_NAME][COLLECTION]
        print(f"\n=== Restore verification with {count:,} documents ===")
        expected_count, expected_checksum = seed_test_data(collection, count)
        print(f"Seeded {expected_count:,} documents. Baseline checksum: {expected_checksum[:16]}...")

        backup_dir, backup_seconds = make_backup(uri, backup_root)
        # Simulate a change after the backup; do not drop the database.
        collection.update_many({}, {"$set": {"verified": False}})
        changed_checksum = checksum_collection(collection)
        print(f"Post-backup data modified. Checksum changed: {changed_checksum != expected_checksum}")

        restore_seconds = restore_backup(uri, backup_dir)
        restored_ok = verify_restore(collection, expected_count, expected_checksum)
        print(f"Backup time: {backup_seconds:.2f}s | Restore time: {restore_seconds:.2f}s")
        if not restored_ok:
            raise RuntimeError("Restore verification failed: count or content checksum mismatch.")
        print("[PASS] Original data recovered and verified.")
    finally:
        client.close()


def benchmark(uri: str, backup_root: Path, counts: list[int]) -> None:
    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
    try:
        client.admin.command("ping")
        collection = client[DB_NAME][COLLECTION]
        print("\n=== Backup/restore benchmark ===")
        print("Documents | Backup (s) | Restore (s) | Integrity")
        print("-" * 55)

        for count in counts:
            expected_count, expected_checksum = seed_test_data(collection, count)
            backup_dir, backup_seconds = make_backup(uri, backup_root)
            collection.update_many({}, {"$set": {"verified": False}})
            restore_seconds = restore_backup(uri, backup_dir)
            ok = verify_restore(collection, expected_count, expected_checksum)
            print(f"{count:9,d} | {backup_seconds:10.2f} | {restore_seconds:11.2f} | {'PASS' if ok else 'FAIL'}")
            if not ok:
                raise RuntimeError(f"Benchmark restore failed for {count} documents.")
    finally:
        client.close()


def hourly_scheduler(uri: str, backup_root: Path) -> None:
    try:
        import schedule
    except ImportError as exc:
        raise RuntimeError("Install the 'schedule' package: pip install schedule") from exc

    def job():
        try:
            make_backup(uri, backup_root)
            apply_retention(backup_root)
        except Exception as exc:
            print(f"[BACKUP WARNING] {exc}", file=sys.stderr)

    job()  # take one backup immediately, then hourly
    schedule.every().hour.do(job)
    print("Hourly backup scheduler started. Press Ctrl+C to stop.")
    while True:
        schedule.run_pending()
        time.sleep(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab 14.2 backup and restore verification")
    parser.add_argument("--mode", choices=["verify", "benchmark", "schedule"], default="verify")
    parser.add_argument("--count", type=int, default=1000, help="Document count for verify mode")
    parser.add_argument("--counts", default="1000,10000,100000", help="Comma-separated benchmark counts")
    parser.add_argument("--backup-dir", default=str(DEFAULT_BACKUP_ROOT))
    args = parser.parse_args()

    uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    backup_root = Path(args.backup_dir).resolve()
    backup_root.mkdir(parents=True, exist_ok=True)

    if not tools_available():
        raise SystemExit("mongodump/mongorestore not found on PATH. Install MongoDB Database Tools first.")

    if args.mode == "verify":
        run_restore_verification(uri, backup_root, args.count)
        apply_retention(backup_root)
    elif args.mode == "benchmark":
        counts = [int(x.strip()) for x in args.counts.split(",") if x.strip()]
        if any(x <= 0 for x in counts):
            raise SystemExit("All benchmark counts must be positive.")
        benchmark(uri, backup_root, counts)
        apply_retention(backup_root)
    else:
        hourly_scheduler(uri, backup_root)


if __name__ == "__main__":
    main()
