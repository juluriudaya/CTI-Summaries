LAB 18 - COMPARATIVE CAPSTONE (MONGODB, CASSANDRA, NEO4J)
========================================================

CONTENTS
--------
lab_01_comparative_capstone.py  Lab 18.1: synthetic dataset + MongoDB benchmarks
lab_02_comparative_report.py    Lab 18.2: generates comparative Markdown report
config/connection.py           MongoDB connection and collection helpers
docker-compose.yml              Dedicated Lab 18 MongoDB service
database_scripts/               Cassandra CQL and Neo4j Cypher reference schemas
requirements.txt                Python dependencies
reports/                        Generated report output folder

IMPORTANT: WHAT THIS PACKAGE CURRENTLY IMPLEMENTS
--------------------------------------------------
The two Python scripts are the supplied lab scripts, retained unchanged.
Lab 18.1 currently generates 10,000 synthetic TRANSACTION records (with
200 marked as fraud), not 100,000 recent THREAT INTELLIGENCE records.
It runs four MongoDB measurements: user transaction history, high-risk
transactions, category aggregation, and a 1,000-document insert batch.

The supplied Lab 18.1 script measures each MongoDB query once per run;
it does NOT perform 10 runs and calculate a median. Cassandra and Neo4j
query equivalents are printed as reference examples; they are NOT
connected or benchmarked by these scripts.

Lab 18.2 re-runs the MongoDB benchmark and writes a Markdown comparison
report under reports/. Cassandra and Neo4j figures are explicitly
architectural estimates, not live measurements. The CQL and Cypher
files are schema/query starting points, not an implemented ingestion
pipeline or live connector.

Thus, this is a complete runnable package for the code supplied and its
MongoDB demonstration, but it is not yet a full 100,000-threat,
three-database benchmark meeting every line of the expanded brief.
Do not report estimates as measured results.

SETUP (WINDOWS POWERSHELL)
--------------------------
1. Extract the ZIP.
2. Open PowerShell in the extracted Lab_18_Comparative_Capstone folder.
3. Create and activate a virtual environment:

   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

4. Install dependencies:

   python -m pip install -r requirements.txt

5. Start the dedicated Lab 18 MongoDB container:

   docker compose up -d mongodb

   This uses host port 27223 and volume lab18_mongo_data.
   It does not use or delete the existing Lab 16 MongoDB container
   or its data volume.

6. Verify the connection:

   $env:MONGO_URI = "mongodb://127.0.0.1:27223"
   python -c "from pymongo import MongoClient; c=MongoClient('mongodb://127.0.0.1:27223',serverSelectionTimeoutMS=5000); print(c.admin.command('ping'))"

   Expected result: {'ok': 1.0}

RUN LAB 18.1
------------
   python lab_01_comparative_capstone.py

This script drops and recreates ONLY capstone.transactions before
inserting its synthetic records. It does not drop the whole database.

RUN LAB 18.2
------------
   python lab_02_comparative_report.py

The generated Markdown report is saved inside the reports folder.

STOP THE LAB 18 CONTAINER
-------------------------
   docker compose down

This keeps the named volume. Do NOT use `docker compose down -v` unless
you intentionally want to delete Lab 18's MongoDB data.

NOTE ON THE EXTENDED THREAT INTELLIGENCE USE CASE
------------------------------------------------
The user-provided use case describes threat sources, threat types,
targets, suspicious source relationships and false-positive analysis.
The supplied Python files instead implement a financial transaction /
fraud example. The included Cassandra and Neo4j files provide starter
schemas aligned to source/type/target threat records, but a true
threat-intelligence implementation requires adapting the generator,
query definitions, and benchmark harness before claiming that objective
is complete.
