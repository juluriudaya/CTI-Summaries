"""Keyless CTI source synchronizer. Runs once at startup, then every six hours."""
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient
import app as cti

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env", override=False)
LOG_PATH = ROOT / "auto_sync.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler()],
)
INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", str(6 * 60 * 60)))


def note(db, source, status, message, count=0):
    doc = {
        "source": source,
        "status": status,
        "message": message,
        "count": count,
        "timestamp": datetime.now(timezone.utc),
    }
    db.sync_log.insert_one(doc)
    logging.info("%s | %s | %s", source, status, message)


def sync_one(client, central, source, fn, *args):
    source_db = client[cti.SOURCE_DB_NAMES[source]]
    cti.ensure_source_db(source_db, source)
    result = fn(source_db, *args)
    cti.merge_source_iocs_to_central(source_db, central, source)
    cti.rebuild_cross_source_threats(central)
    if isinstance(result, tuple):
        count = int(result[0] or 0)
    elif isinstance(result, int):
        count = result
    else:
        count = source_db.cti_iocs.estimated_document_count()
    note(central, source, "success", f"Scheduled sync completed; {count} records processed", count)


def run_cycle():
    uri = os.getenv("MONGODB_URI", "mongodb://mongo:27017")
    central_name = os.getenv("MONGODB_DB", "cyber_threat_intelligence")
    client = MongoClient(uri, serverSelectionTimeoutMS=10000, connectTimeoutMS=10000)
    try:
        client.admin.command("ping")
        central = client[central_name]
        cti.ensure_indexes(central)
        for source, dbname in cti.SOURCE_DB_NAMES.items():
            cti.ensure_source_db(client[dbname], source)
        logging.info("Starting keyless CTI sync cycle")
        jobs = [
            ("OpenPhish", cti.sync_openphish, (500,)),
            ("CTI Digest", cti.sync_cti_digest, ()),
            ("CISA KEV", cti.sync_cisa_kev, (5000,)),
            ("Feodo Tracker", cti.sync_feodo_tracker, (1000,)),
        ]
        malwarebazaar_key = os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip()
        if malwarebazaar_key:
            jobs.append(("MalwareBazaar", cti.sync_malwarebazaar, (malwarebazaar_key, 100)))
        else:
            note(central, "MalwareBazaar", "configuration_required", "Optional hash feed skipped: set MALWAREBAZAAR_AUTH_KEY to enable it")
        for source, fn, args in jobs:
            try:
                sync_one(client, central, source, fn, *args)
            except Exception as exc:
                note(central, source, "error", f"{type(exc).__name__}: {str(exc)[:900]}")
                logging.exception("Source sync failed: %s", source)
        logging.info("CTI sync cycle finished")
    finally:
        client.close()


if __name__ == "__main__":
    while True:
        try:
            load_dotenv(ROOT / ".env", override=False)
            run_cycle()
        except Exception:
            logging.exception("Sync cycle failed; will retry next cycle")
        logging.info("Sleeping for %s seconds", INTERVAL_SECONDS)
        time.sleep(INTERVAL_SECONDS)
