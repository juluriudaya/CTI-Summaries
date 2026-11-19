"""
Lab 11 workload runner.
Commands:
  python lab11_workload.py seed --source-uri mongodb://localhost:27117
  python lab11_workload.py 111
  python lab11_workload.py 112
  python lab11_workload.py reshard
  python lab11_workload.py status

All Lab 11 writes go through mongos at localhost:27317.
The source Lab 7 collection is READ ONLY; records are copied into Lab 11.
"""
import argparse, random, hashlib, time, json
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient, ASCENDING, HASHED
from pymongo.errors import PyMongoError

ROUTER = "mongodb://localhost:27317/?serverSelectionTimeoutMS=8000"
DB_NAME = "cti_shard"
TARGET_COUNT = 6000

def client(uri=ROUTER):
    c = MongoClient(uri)
    c.admin.command("ping")
    return c

def make_sightings(source_docs, n=TARGET_COUNT):
    if not source_docs:
        raise RuntimeError("No source threat records were read from Lab 7.")
    rng = random.Random(11)
    # Weighted sampling makes a few real threat IDs more popular, modelling skew.
    weights = [1.0 / ((i + 1) ** 0.72) for i in range(len(source_docs))]
    docs = []
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(n):
        src = rng.choices(source_docs, weights=weights, k=1)[0]
        tid = str(src.get("cveID") or src.get("cve_id") or src.get("indicator") or src.get("_id"))
        title = str(src.get("vulnerabilityName") or src.get("title") or src.get("name") or tid)
        source_id = str(src.get("vendorProject") or src.get("source") or "CISA-KEV")
        docs.append({
            "sighting_id": f"SIGHT-{i:07d}",
            "threat_id": tid,
            "source_id": source_id,
            "title": title[:500],
            "seen_at": start + timedelta(seconds=i),
            "user_id": f"user-{i % 500:04d}",
            "payload": {"source_record_id": str(src.get("_id", ""))}
        })
    return docs

def seed(args):
    src = MongoClient(args.source_uri, serverSelectionTimeoutMS=8000)
    src.admin.command("ping")
    source_col = src[args.source_db][args.source_collection]
    source_docs = list(source_col.find({}, limit=5000))
    print(f"Read {len(source_docs)} source documents from {args.source_db}.{args.source_collection}")
    if not source_docs:
        raise RuntimeError("Source collection is empty. Check Lab 7 URI/database/collection.")
    docs = make_sightings(source_docs, args.count)
    c = client()
    db = c[DB_NAME]
    # Dedicated Lab 11 collection only; no source DB is modified.
    db.sightings.drop()
    db.sightings.insert_many(docs, ordered=False)
    print(f"Copied and expanded source data into {DB_NAME}.sightings: {len(docs)} documents")
    print("Lab 7 source was read only; Lab 11 data is an independent copy.")
    c.close(); src.close()

def enable_db(dbname=DB_NAME):
    c=client()
    try: c.admin.command("enableSharding", dbname)
    except PyMongoError as e:
        if "already enabled" not in str(e).lower(): raise
    c.close()

def shard_collection(dbname, coll, key):
    c=client()
    try:
        c.admin.command("shardCollection", f"{dbname}.{coll}", key=key)
    except PyMongoError as e:
        if "already sharded" not in str(e).lower(): raise
    c.close()

def counts(collname):
    c=client()
    try:
        r=c.admin.command("listCollections", 1, filter={"name":collname}, cursor={})
        # sharded distribution is available from collStats.
        stats=c[DB_NAME].command("collStats", collname)
        print(f"{collname}: total={stats.get('count')} chunks={stats.get('nchunks','n/a')}")
        print("shards:", json.dumps(stats.get("shards",{}), default=str))
    finally: c.close()

def run111():
    c=client(); db=c[DB_NAME]
    enable_db()
    # Each candidate has its own collection so candidate keys can be tested independently.
    source=list(db.sightings.find({}, {"_id":0}).limit(TARGET_COUNT))
    if not source: raise RuntimeError("Run the seed command first.")
    candidates=[
        ("sighting_id_range", {"sighting_id":1}),
        ("threat_id_range", {"threat_id":1}),
        ("seen_at_range", {"seen_at":1}),
        ("threat_id_hashed", {"threat_id":"hashed"}),
    ]
    for name,key in candidates:
        col=db[name]
        col.drop()
        col.insert_many(source, ordered=False)
        col.create_index(list(key.items()))
        c.admin.command("shardCollection", f"{DB_NAME}.{name}", key=key)
        print(f"Created {name} with shard key {key}")
    print("\nCandidate cardinality and query examples:")
    for name,key in candidates:
        col=db[name]
        field=next(iter(key))
        cardinality=col.distinct(field)
        print(f"{name}: distinct({field})={len(cardinality)}")
    print("\nUse mongos explain in mongosh for exact shard targeting:")
    print("db.sightings.find({threat_id:'<one copied threat id>'}).explain('executionStats')")
    c.close()

def run112():
    c=client(); db=c[DB_NAME]; enable_db()
    db.hotspot_data.drop(); db.even_data.drop()
    n=10000
    start=datetime(2026,1,1,tzinfo=timezone.utc)
    monotonic=[{"ts":start+timedelta(seconds=i),"user_id":f"user-{i%500:04d}"} for i in range(n)]
    hashed=[{"user_id":f"user-{i%500:04d}","seq":i} for i in range(n)]
    db.hotspot_data.insert_many(monotonic, ordered=False)
    db.even_data.insert_many(hashed, ordered=False)
    db.hotspot_data.create_index([("ts", ASCENDING)])
    db.even_data.create_index([("user_id", HASHED)])
    c.admin.command("shardCollection",f"{DB_NAME}.hotspot_data",key={"ts":1})
    c.admin.command("shardCollection",f"{DB_NAME}.even_data",key={"user_id":"hashed"})
    print("Inserted 10,000 documents into each collection.")
    print("hotspot_data uses increasing ts; even_data uses hashed user_id.")
    print("Inspect chunk and shard distribution after balancer activity with:")
    print("mongosh 'mongodb://localhost:27317' --eval \"sh.status()\"")
    print("Range query explain: db.hotspot_data.find({ts:{$gte:ISODate('2026-01-01'),$lt:ISODate('2026-01-02')}}).explain()")
    print("Hashed range explain: db.even_data.find({user_id:{$gte:'user-0001',$lt:'user-0100'}}).explain()")
    c.close()

def reshard():
    c=client()
    print("Resharding hotspot_data from {ts:1} to {ts:'hashed'} ...")
    result=c.admin.command({"reshardCollection":f"{DB_NAME}.hotspot_data","key":{"ts":"hashed"}})
    print(json.dumps(result,default=str,indent=2))
    c.close()

def status():
    c=client()
    print("mongos ping:",c.admin.command("ping"))
    print("sharding status:")
    print(c.admin.command("listShards"))
    print("databases:",c.admin.command("listDatabases")["databases"])
    c.close()

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)
    s=sub.add_parser("seed"); s.add_argument("--source-uri",default="mongodb://localhost:27117/?directConnection=true"); s.add_argument("--source-db",default="cti_cisa_kev"); s.add_argument("--source-collection",default="indicators"); s.add_argument("--count",type=int,default=TARGET_COUNT)
    sub.add_parser("111"); sub.add_parser("112"); sub.add_parser("reshard"); sub.add_parser("status")
    a=ap.parse_args()
    {"seed":seed,"111":lambda _:run111(),"112":lambda _:run112(),"reshard":lambda _:reshard(),"status":lambda _:status()}[a.cmd](a)

if __name__=="__main__":
    main()
