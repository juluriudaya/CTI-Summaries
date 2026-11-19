import os
import random
import time
import statistics
import json
from datetime import datetime, timedelta, date
from collections import defaultdict
from pymongo import MongoClient, InsertOne
from cassandra.cluster import Cluster
from cassandra.concurrent import execute_concurrent_with_args
from neo4j import GraphDatabase

# ============================================================
# LAB 18: THREAT INTELLIGENCE - THREE DATABASE COMPARISON
# ============================================================

TOTAL_RECORDS = 100_000
REPEATS = 10
BATCH_SIZE = 1000
random.seed(42)

MONGO_URI = "mongodb://127.0.0.1:27224"
CASSANDRA_HOST = "127.0.0.1"
CASSANDRA_PORT = 9043
NEO4J_URI = "bolt://127.0.0.1:7688"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
if not NEO4J_PASSWORD:
    raise RuntimeError("Set NEO4J_PASSWORD in your environment before connecting to Neo4j.")

sources = [f"SRC-{i:03d}" for i in range(20)]
targets = [f"TARGET-{i:03d}" for i in range(40)]
types = ["Malware", "Phishing", "Ransomware", "Botnet", "DDoS"]
indicators = [f"IOC-{i:04d}" for i in range(500)]

def generate_records():
    records = []
    now = datetime.utcnow()

    for i in range(TOTAL_RECORDS):
        ts = now - timedelta(
            days=random.randint(0, 6),
            seconds=random.randint(0, 86399)
        )
        records.append({
            "threat_id": f"THREAT-{i:07d}",
            "from_source": random.choice(sources),
            "timestamp": ts,
            "event_date": ts.date(),
            "threat_type": random.choice(types),
            "indicator": random.choice(indicators),
            "target": random.choice(targets),
            "confidence": round(random.uniform(0.1, 1.0), 3),
            "is_false_positive": random.random() < 0.08
        })
    return records

def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]

def connect_databases():
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    mongo_client.admin.command("ping")
    mongo = mongo_client["threat_intelligence"]

    cluster = Cluster([CASSANDRA_HOST], port=CASSANDRA_PORT)
    cassandra_session = cluster.connect("threat_intelligence")

    neo_driver = GraphDatabase.driver(
        NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
    )
    neo_driver.verify_connectivity()

    print("[OK] MongoDB connected")
    print("[OK] Cassandra connected")
    print("[OK] Neo4j connected")
    return mongo_client, mongo, cluster, cassandra_session, neo_driver

def load_mongodb(db, records):
    db.threats.delete_many({})
    db.sources.delete_many({})

    start = time.perf_counter()
    for batch in chunks(records, BATCH_SIZE):
        mongo_batch = [
            {**record, "event_date": record["event_date"].isoformat()}
            for record in batch
        ]
        db.threats.insert_many(mongo_batch, ordered=False)

    grouped = defaultdict(list)
    for r in records:
        grouped[r["from_source"]].append(r)

    source_docs = []
    for source, items in grouped.items():
        items.sort(key=lambda x: x["timestamp"], reverse=True)
        source_docs.append({
            "source_id": source,
            "full_threats": [x["threat_id"] for x in items],
            "recent_threats": [
                {
                    "threat_id": x["threat_id"],
                    "threat_type": x["threat_type"],
                    "indicator": x["indicator"],
                    "timestamp": x["timestamp"]
                }
                for x in items[:50]
            ]
        })

    db.sources.insert_many(source_docs)
    elapsed = time.perf_counter() - start
    print(f"[MongoDB] Loaded {len(records):,} threats in {elapsed:.2f}s")
    return elapsed

def load_cassandra(session, records):
    session.execute("""
        TRUNCATE threats_by_source
    """)
    session.execute("""
        TRUNCATE threats_by_type
    """)
    session.execute("""
        TRUNCATE threats_by_target
    """)

    source_stmt = session.prepare("""
        INSERT INTO threats_by_source
        (source_id,event_date,timestamp,threat_id,threat_type,
         indicator,target,confidence)
        VALUES (?,?,?,?,?,?,?,?)
    """)
    type_stmt = session.prepare("""
        INSERT INTO threats_by_type
        (threat_type,event_date,timestamp,threat_id,source_id,
         indicator,target,confidence)
        VALUES (?,?,?,?,?,?,?,?)
    """)
    target_stmt = session.prepare("""
        INSERT INTO threats_by_target
        (target,event_date,timestamp,threat_id,source_id,
         threat_type,indicator,confidence)
        VALUES (?,?,?,?,?,?,?,?)
    """)

    args_source, args_type, args_target = [], [], []
    for r in records:
        common = (
            r["event_date"], r["timestamp"], r["threat_id"],
            r["threat_type"], r["indicator"], r["target"],
            r["confidence"]
        )
        args_source.append((r["from_source"],) + common)
        args_type.append((
            r["threat_type"], r["event_date"], r["timestamp"],
            r["threat_id"], r["from_source"], r["indicator"],
            r["target"], r["confidence"]
        ))
        args_target.append((
            r["target"], r["event_date"], r["timestamp"],
            r["threat_id"], r["from_source"], r["threat_type"],
            r["indicator"], r["confidence"]
        ))

    start = time.perf_counter()
    for stmt, args in [
        (source_stmt, args_source),
        (type_stmt, args_type),
        (target_stmt, args_target)
    ]:
        results = execute_concurrent_with_args(
            session, stmt, args, concurrency=50,
            raise_on_first_error=True
        )
        if not all(success for success, _ in results):
            raise RuntimeError("A Cassandra insert failed")

    elapsed = time.perf_counter() - start
    print(f"[Cassandra] Loaded {len(records):,} threats into 3 tables in {elapsed:.2f}s")
    return elapsed

def load_neo4j(driver, records):
    start = time.perf_counter()

    with driver.session() as session:
        session.run("MATCH (t:Threat) DETACH DELETE t").consume()
        session.run("MATCH (s:Source) DETACH DELETE s").consume()

        session.run("""
            UNWIND $sources AS source
            CREATE (:Source {source_id: source})
        """, sources=sources).consume()

        query = """
            UNWIND $rows AS row
            MATCH (s:Source {source_id: row.from_source})
            CREATE (t:Threat {
                threat_id: row.threat_id,
                timestamp: row.timestamp,
                event_date: row.event_date,
                threat_type: row.threat_type,
                indicator: row.indicator,
                target: row.target,
                confidence: row.confidence,
                is_false_positive: row.is_false_positive
            })
            CREATE (s)-[:REPORTS]->(t)
        """

        for batch in chunks(records, BATCH_SIZE):
            rows = []
            for r in batch:
                rows.append({
                    **r,
                    "timestamp": r["timestamp"].isoformat(),
                    "event_date": r["event_date"].isoformat()
                })
            session.run(query, rows=rows).consume()

        # Link sources sharing indicators.
        session.run("""
            MATCH (s:Source)-[:REPORTS]->(t:Threat)
            WITH t.indicator AS indicator, collect(DISTINCT s) AS srcs
            WHERE size(srcs) > 1
            UNWIND srcs AS a
            UNWIND srcs AS b
            WITH indicator, a, b
            WHERE a.source_id < b.source_id
            MERGE (a)-[r:SUSPICIOUS {indicator: indicator}]->(b)
        """).consume()

    elapsed = time.perf_counter() - start
    print(f"[Neo4j] Loaded {len(records):,} threats in {elapsed:.2f}s")
    return elapsed


def benchmark_mongo(db, sample):
    source = sample["from_source"]
    target = sample["target"]
    day = sample["event_date"]
    day_start = datetime.combine(day, datetime.min.time())
    day_end = day_start + timedelta(days=1)

    return [
        lambda: db.threats.find({
            "from_source": source,
            "event_date": day.isoformat()
        }).sort("timestamp", -1).limit(100).to_list(),
        lambda: db.threats.find({
            "target": target,
            "event_date": day.isoformat()
        }).limit(100).to_list(),
        lambda: list(db.threats.aggregate([
            {"$match": {"timestamp": {"$gte": day_start, "$lt": day_end}}},
            {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}}
        ]))
    ]


def benchmark_cassandra(session, sample):
    source_q = session.prepare("""
        SELECT threat_id FROM threats_by_source
        WHERE source_id=? AND event_date=? LIMIT 100
    """)
    target_q = session.prepare("""
        SELECT threat_id FROM threats_by_target
        WHERE target=? AND event_date=? LIMIT 100
    """)
    type_q = session.prepare("""
        SELECT threat_id FROM threats_by_type
        WHERE threat_type=? AND event_date=?
    """)

    def daily_volume():
        totals = {}
        for threat_type in types:
            rows = session.execute(
                type_q, (threat_type, sample["event_date"])
            )
            totals[threat_type] = sum(1 for _ in rows)
        return totals

    return [
        lambda: session.execute(
            source_q, (sample["from_source"], sample["event_date"])
        ).all(),
        lambda: session.execute(
            target_q, (sample["target"], sample["event_date"])
        ).all(),
        daily_volume
    ]


def benchmark_neo4j(driver, sample):
    day = sample["event_date"].isoformat()
    queries = [
        ("""
        MATCH (:Source {source_id:$source})-[:REPORTS]->(t:Threat)
        WHERE t.event_date = $day
        RETURN t LIMIT 100
        """, {"source": sample["from_source"], "day": day}),
        ("""
        MATCH (t:Threat {target:$target, event_date:$day})
        RETURN t LIMIT 100
        """, {"target": sample["target"], "day": day}),
        ("""
        MATCH (t:Threat {event_date:$day})
        RETURN t.threat_type AS type, count(*) AS total
        """, {"day": day})
    ]

    return [
        lambda q=q, p=p: run_neo_query(driver, q, p)
        for q, p in queries
    ]


def run_neo_query(driver, query, params):
    with driver.session() as session:
        return list(session.run(query, **params))


def benchmark_write_throughput(mongo, cassandra_session, neo_driver, sample):
    mongo_collection = mongo["benchmark_writes"]

    cassandra_insert = cassandra_session.prepare("""
        INSERT INTO write_test
        (batch_id, threat_id, timestamp, source_id, threat_type,
         indicator, target, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """)

    results = {}
    database_names = ["MongoDB", "Cassandra", "Neo4j"]

    print("\\n=== WRITE THROUGHPUT BENCHMARK (1,000 RECORDS PER RUN) ===")

    for database in database_names:
        timings = []

        for run_number in range(REPEATS):
            batch_id = f"WB-{database}-{run_number}"

            rows = [{
                "threat_id": f"{batch_id}-{i:05d}",
                "timestamp": datetime.utcnow(),
                "from_source": sample["from_source"],
                "threat_type": types[i % len(types)],
                "indicator": f"WRITE-IOC-{i:05d}",
                "target": sample["target"],
                "confidence": 0.95
            } for i in range(BATCH_SIZE)]

            start = time.perf_counter()

            if database == "MongoDB":
                mongo_collection.insert_many([
                    {"batch_id": batch_id, **row} for row in rows
                ], ordered=False)

            elif database == "Cassandra":
                params = [
                    (
                        batch_id,
                        row["threat_id"],
                        row["timestamp"],
                        row["from_source"],
                        row["threat_type"],
                        row["indicator"],
                        row["target"],
                        row["confidence"]
                    )
                    for row in rows
                ]
                write_results = execute_concurrent_with_args(
                    cassandra_session,
                    cassandra_insert,
                    params,
                    concurrency=100,
                    raise_on_first_error=True
                )
                if not all(success for success, _ in write_results):
                    raise RuntimeError("Some Cassandra benchmark writes failed")

            else:
                with neo_driver.session() as session:
                    session.run("""
                        UNWIND $rows AS row
                        CREATE (:WriteTest {
                            batch_id: row.batch_id,
                            threat_id: row.threat_id,
                            timestamp: row.timestamp,
                            source_id: row.source_id,
                            threat_type: row.threat_type,
                            indicator: row.indicator,
                            target: row.target,
                            confidence: row.confidence
                        })
                    """, rows=[
                        {
                            "batch_id": batch_id,
                            "threat_id": row["threat_id"],
                            "timestamp": row["timestamp"].isoformat(),
                            "source_id": row["from_source"],
                            "threat_type": row["threat_type"],
                            "indicator": row["indicator"],
                            "target": row["target"],
                            "confidence": row["confidence"]
                        }
                        for row in rows
                    ]).consume()

            elapsed = time.perf_counter() - start
            timings.append(elapsed * 1000)

            # Remove this trial's data outside the timed interval.
            if database == "MongoDB":
                mongo_collection.delete_many({"batch_id": batch_id})
            elif database == "Cassandra":
                cassandra_session.execute(
                    "DELETE FROM write_test WHERE batch_id=%s",
                    (batch_id,)
                )
            else:
                with neo_driver.session() as session:
                    session.run(
                        "MATCH (n:WriteTest {batch_id:$batch_id}) DELETE n",
                        batch_id=batch_id
                    ).consume()

        median_ms = statistics.median(timings)
        throughput = BATCH_SIZE / (median_ms / 1000)

        results[database] = {
            "median_ms": round(median_ms, 3),
            "records_per_second": round(throughput, 2)
        }

        print(
            f"{database:10s} | median {median_ms:.3f} ms"
            f" | {throughput:,.2f} records/sec"
        )

    return results


def run_benchmarks(mongo, cassandra_session, neo_driver, sample):
    functions = {
        "MongoDB": benchmark_mongo(mongo, sample),
        "Cassandra": benchmark_cassandra(cassandra_session, sample),
        "Neo4j": benchmark_neo4j(neo_driver, sample)
    }

    names = [
        "Threat history by source",
        "Target and spread lookup",
        "Daily/type volume lookup"
    ]

    results = {}
    print("\\n=== 10-RUN QUERY BENCHMARKS (MEDIAN) ===")

    for database, tests in functions.items():
        results[database] = {}

        for name, test in zip(names, tests):
            timings = []

            for _ in range(REPEATS):
                start = time.perf_counter()
                test()
                timings.append((time.perf_counter() - start) * 1000)

            median = statistics.median(timings)
            results[database][name] = round(median, 3)

            print(
                f"{database:10s} | {name:32s} | median {median:.3f} ms"
            )

    write_results = benchmark_write_throughput(
        mongo, cassandra_session, neo_driver, sample
    )

    for database, values in write_results.items():
        results[database]["Write throughput - median ms"] = values["median_ms"]
        results[database]["Write throughput - records/sec"] = values["records_per_second"]

    return results

def false_positive_analysis(db, driver):
    mongo_result = list(db.threats.aggregate([
        {"$group": {
            "_id": "$from_source",
            "total": {"$sum": 1},
            "false_positives": {
                "$sum": {"$cond": ["$is_false_positive", 1, 0]}
            }
        }}
    ]))

    with driver.session() as session:
        graph_result = list(session.run("""
            MATCH (a:Source)-[r:SUSPICIOUS]->(b:Source)
            RETURN a.source_id AS source_a,
                   b.source_id AS source_b,
                   count(r) AS shared_indicators
            ORDER BY shared_indicators DESC
            LIMIT 20
        """))

    print("\n=== FALSE-POSITIVE ANALYSIS BY SOURCE ===")
    for item in mongo_result:
        rate = item["false_positives"] / item["total"] * 100
        print(
            f'{item["_id"]}: {item["false_positives"]}/'
            f'{item["total"]} ({rate:.2f}%)'
        )

    print("\n=== TOP SUSPICIOUS SOURCE PAIRS ===")
    for item in graph_result:
        print(dict(item))


def write_report(results, load_times, record_count):
    from pathlib import Path

    Path("reports").mkdir(exist_ok=True)
    filename = "reports/threat_intelligence_benchmark.md"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("# Lab 18: Threat Intelligence Comparative Benchmark\n\n")
        f.write(f"- Records generated: {record_count:,}\n")
        f.write(f"- Query repetitions: {REPEATS}\n")
        f.write(f"- Write benchmark: {REPEATS} runs of {BATCH_SIZE:,} records per database\n")
        f.write("- Query metric: median latency in milliseconds\n")
        f.write("- Write metric: median batch latency and records per second\n")
        f.write("- All three databases use dedicated local instances\n\n")

        f.write("## Data ingestion time\n\n")
        f.write("| Database | Ingestion time (seconds) |\n|---|---:|\n")
        for db, value in load_times.items():
            f.write(f"| {db} | {value:.3f} |\n")

        f.write("\n## Query performance (median milliseconds)\n\n")
        f.write("| Database | Query | Median latency (ms) |\n|---|---|---:|\n")
        for db, queries in results.items():
            for query, value in queries.items():
                if query in (
                    "Threat history by source",
                    "Target and spread lookup",
                    "Daily/type volume lookup"
                ):
                    f.write(f"| {db} | {query} | {value:.3f} |\n")

        f.write("\n## Write throughput\n\n")
        f.write("| Database | Median batch latency (ms) | Records per second |\n")
        f.write("|---|---:|---:|\n")
        for db, queries in results.items():
            latency = queries.get("Write throughput - median ms")
            throughput = queries.get("Write throughput - records/sec")
            if latency is not None and throughput is not None:
                f.write(f"| {db} | {latency:.3f} | {throughput:,.2f} |\n")

        f.write("\n## False-positive analysis\n\n")
        f.write(
            "False-positive labels are synthetically generated for this experiment. "
            "They are analyzed separately and are not used as a database performance query.\n"
        )

        f.write("\n## Methodology and limitations\n\n")
        f.write(
            "The experiment uses synthetic threat records and local database instances. "
            "Cassandra daily volume analytics uses five partition queries and counts "
            "the returned rows in Python because Cassandra does not provide the same "
            "general-purpose aggregation model as MongoDB. Query timings therefore "
            "include different database execution paths. Write throughput measures "
            "batches of 1,000 records over 10 runs. Results describe this local setup "
            "and should not be treated as production cluster performance.\n"
        )

    print(f"\n[OK] Report saved to {filename}")


def main():
    print("=" * 65)
    print("LAB 18 - THREAT INTELLIGENCE THREE-DATABASE EXPERIMENT")
    print("=" * 65)

    records = generate_records()
    print(f"[OK] Generated {len(records):,} synthetic threat records")

    mongo_client, mongo, cluster, cassandra_session, neo_driver = connect_databases()

    try:
        load_times = {
            "MongoDB": load_mongodb(mongo, records),
            "Cassandra": load_cassandra(cassandra_session, records),
            "Neo4j": load_neo4j(neo_driver, records)
        }

        sample = records[0]
        results = run_benchmarks(
            mongo, cassandra_session, neo_driver, sample
        )

        false_positive_analysis(mongo, neo_driver)
        write_report(results, load_times, len(records))

        print("\n[COMPLETE] Lab 18 threat-intelligence experiment finished.")

    finally:
        mongo_client.close()
        cassandra_session.shutdown()
        cluster.shutdown()
        neo_driver.close()

if __name__ == "__main__":
    main()
