# Lab 11 – MongoDB Sharding (isolated setup)

## Safety and relationship to Labs 7–10
This Lab 11 environment is intentionally isolated in Docker network `lab11_sharding_net`.
It does NOT stop, remove, recreate, or alter your existing Lab 7, Lab 8/9, Lab 10 containers,
networks, or volumes. Do not run `docker compose down -v`, `docker system prune`, or remove volumes.

The reference report links the labs conceptually:
- Lab 7 supplies the ThreatLens/CTI workload. Lab 11 will COPY selected source records.
- Lab 8's replica-set design is reused for config servers and each shard.
- Lab 9's partition test is repeated against one shard only.
- Lab 10's transaction pattern is compared for same-shard and cross-shard transfers.
- Lab 11 adds the mongos router and two shards.

The source report uses 3 config-server nodes + 3 nodes per shard + mongos.

## Requirements
- Docker Desktop running (Linux containers)
- Python 3.10+
- PowerShell
- Python packages: `pip install -r requirements.txt`

## Step 1 – start only the new Lab 11 containers
From this folder:
```powershell
docker compose up -d
docker compose ps
```
Expected: 9 mongod containers and 1 mongos container. Wait until all are running.

## Step 2 – initialize replica sets and add shards
```powershell
python setup_cluster.py
```
Router endpoint: `mongodb://localhost:27317`

## Important
Do not use Lab 10's `docker compose down` or touch its volumes. Do not expose Lab 11 by attaching it to Lab 10's Docker network.
If you want to stop Lab 11 after the experiment, use `docker compose stop` (not `down -v`).

The reference report contains measured sample values from another student's run. Do not copy those values into your report as your own. Your actual output will be collected from your execution.

## Lab tasks
The next scripts are built to run through the mongos router. Complete the cluster setup first. Then run the workload/data import script provided in the next stage. Partition and cross-shard transaction tests should only be run after baseline checks, with explicit reconnect steps.


## Step 3 – install Python dependencies
```powershell
python -m pip install -r requirements.txt
```

## Step 4 – copy real Lab 7 threat data (source is read-only)
Make sure your existing Lab 7 cluster is running and port 27117 is available.
```powershell
python lab11_workload.py seed
```
Default source: `cti_cisa_kev.indicators` through `localhost:27117`.
This copies selected fields into the new Lab 11 database `cti_shard.sightings`.
It does not write to or alter Lab 7.

If your Lab 7 source uses another port/database/collection, specify:
```powershell
python lab11_workload.py seed --source-uri "mongodb://localhost:27117/?directConnection=true" --source-db cti_cisa_kev --source-collection indicators
```

## Step 5 – Lab 11.1 and 11.2
```powershell
python lab11_workload.py 111
python lab11_workload.py 112
python lab11_workload.py status
```
The workload script creates candidate collections and hotspot/even-distribution collections in `cti_shard`.
Inspect chunk placement and explain output through mongosh:
```powershell
mongosh "mongodb://localhost:27317"
sh.status()
use cti_shard
db.hotspot_data.find({ts:{$gte:ISODate("2026-01-01"),$lt:ISODate("2026-01-02")}}).explain("executionStats")
db.even_data.find({user_id:{$gte:"user-0001",$lt:"user-0100"}}).explain("executionStats")
```

## Step 6 – optional resharding activity
Only after recording the initial distribution:
```powershell
python lab11_workload.py reshard
```
This changes Lab 11's own `cti_shard.hotspot_data` shard key from ranged `ts` to hashed `ts`. It does not affect Lab 7 or Lab 10.

## Lab 11.3 and 11.4
These are intentionally not automated in this starter because they involve network isolation and multi-document transactions. First verify the cluster, shard distribution, and copied data. Then ask for the guided 11.3 procedure. We will disconnect only `lab11-s2b` and `lab11-s2c` from `lab11_sharding_net`, never the earlier Lab 7–10 networks. We will reconnect both immediately after the test.
