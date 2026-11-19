"""Lab 9.1: benchmark MongoDB write concern and journaling latency.

Run inside the Lab 8 Docker network. MongoDB replica-set members are expected
at mongo-rs0-1:27017, mongo-rs0-2:27017 and mongo-rs0-3:27017.
MongoDB does not support w='all'; w=2 is included as the all-data-bearing
members setting for this two-data-bearing-member + arbiter replica set.
"""
import os
import time
from pymongo import MongoClient, WriteConcern
from pymongo.errors import PyMongoError

URI = os.getenv(
    "REPLICA_SET_URI",
    "mongodb://mongo-rs0-1:27017,mongo-rs0-2:27017,mongo-rs0-3:27017/"
    "?replicaSet=rs0&serverSelectionTimeoutMS=10000",
)
DOC_COUNT = int(os.getenv("DOC_COUNT", "1000"))
DB_NAME = os.getenv("DB_NAME", "lab_9_1_write_concern")


def run_case(client, w_value, journal, label):
    db = client[DB_NAME]
    name = f"writes_{label}"
    db.drop_collection(name)
    collection = db.get_collection(
        name, write_concern=WriteConcern(w=w_value, j=journal, wtimeout=15000)
    )
    elapsed_each = []
    start_total = time.perf_counter()
    for i in range(DOC_COUNT):
        doc = {"sequence": i, "label": label, "created_at_ns": time.time_ns()}
        start = time.perf_counter()
        collection.insert_one(doc)
        elapsed_each.append(time.perf_counter() - start)
    total_s = time.perf_counter() - start_total
    sorted_ms = sorted(x * 1000 for x in elapsed_each)
    avg_ms = sum(sorted_ms) / len(sorted_ms)
    p50_ms = sorted_ms[len(sorted_ms) // 2]
    p99_ms = sorted_ms[min(int(len(sorted_ms) * 0.99), len(sorted_ms) - 1)]
    count = db[name].count_documents({})
    return total_s, avg_ms, p50_ms, p99_ms, count


def main():
    print("=" * 82)
    print("LAB 9.1: MEASURE WRITE CONCERN LATENCY")
    print("=" * 82)
    print(f"Replica-set URI: {URI}")
    print(f"Documents per configuration: {DOC_COUNT}")
    print("MongoDB does not accept w='all'. This run tests w:1, w:majority and w:2.")
    print("w:2 waits for both data-bearing members in this replica set; the arbiter stores no data.\n")

    client = MongoClient(URI, serverSelectionTimeoutMS=10000)
    results = []
    try:
        client.admin.command("ping")
        hello = client.admin.command("hello")
        print(f"[OK] Connected. Replica set: {hello.get('setName', 'unknown')}\n")
        cases = [
            (1, False, "w1_jfalse", "w:1, j:false"),
            (1, True, "w1_jtrue", "w:1, j:true"),
            ("majority", False, "majority_jfalse", "w:majority, j:false"),
            ("majority", True, "majority_jtrue", "w:majority, j:true"),
            (2, False, "w2_jfalse", "w:2, j:false"),
            (2, True, "w2_jtrue", "w:2, j:true"),
        ]
        for w, journal, key, label in cases:
            print(f"Running {label} ...", flush=True)
            try:
                total, avg, p50, p99, count = run_case(client, w, journal, key)
                results.append((label, total, avg, p50, p99, count, "OK"))
                print(f"  {count}/{DOC_COUNT} docs; total={total:.3f}s; avg={avg:.3f}ms/write", flush=True)
            except PyMongoError as exc:
                results.append((label, None, None, None, None, 0, f"FAILED: {exc}"))
                print(f"  FAILED: {exc}", flush=True)

        print("\nRESULTS")
        print(f"{'Configuration':<25} {'Total(s)':>10} {'Avg(ms)':>10} {'P50(ms)':>10} {'P99(ms)':>10} {'Count':>8}  Status")
        print("-" * 105)
        for label, total, avg, p50, p99, count, status in results:
            if total is None:
                print(f"{label:<25} {'-':>10} {'-':>10} {'-':>10} {'-':>10} {count:>8}  {status}")
            else:
                print(f"{label:<25} {total:>10.3f} {avg:>10.3f} {p50:>10.3f} {p99:>10.3f} {count:>8}  {status}")
        print("\nInterpret measured results rather than assuming a fixed speed ratio.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
