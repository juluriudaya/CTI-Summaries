# 🎓 Comprehensive Faculty Viva & Defense Guide: Labs 7 to 18
**Student Preparation Guide for NoSQL Distributed Systems Evaluation**

---

## 📌 Executive Opening for Your Faculty (1 Minute Pitch)
> *"Good morning, Professor. Our project is the **CTI (Cyber Threat Intelligence) Fusion Center**. We have designed **Lab 7** as a centralized operations hub and connected all subsequent advanced experiments—**Labs 8 through 18**—directly into it. Rather than running isolated scripts, our centralized platform continuously ingests live threat feeds, normalizes indicators, coordinates distributed MongoDB replica sets, evaluates write latencies, enforces ACID transactions, tests horizontal sharding, manages multi-tenancy, and integrates polyglot and AI vector search capabilities—all verified with automated test suites."*

---

## 🔬 Experiment-by-Experiment Faculty Walkthrough

---

### 🧩 Lab 7.1: Production Threat Intelligence Schema Modeling
* **Objective:** Analyze a production MongoDB threat-intelligence schema, evaluate embedding vs. referencing decisions, and enforce the 16 MB BSON document boundary.
* **Core Technical Concept:**
  - **Embedding (1-to-Few):** Used when data is tightly coupled and accessed together (e.g., threat tags, timestamps, source provenance inside an IOC document). Eliminates expensive `$lookup` / JOIN operations.
  - **Referencing (1-to-Many / Unbounded):** Used when child collections grow indefinitely (e.g., millions of sighting logs linked to an IP, or large PDF security advisories). Prevents exceeding MongoDB's **16 MB document size limit**.
  - **Size Verification:** Verified via aggregation pipeline:
    ```javascript
    db.threats.aggregate([
      { $project: { docSize: { $bsonSize: "$$ROOT" } } },
      { $group: { _id: null, avgSize: { $avg: "$docSize" }, maxSize: { $max: "$docSize" } } }
    ]);
    ```
* **Activity 7.1 Solution (Try it yourself):**
  - *Redesign Question:* "Redesign a referencing relationship (threat sources) into an embedded array. What queries become faster? What becomes harder?"
  - *Answer to Faculty:* **Faster:** Single-document reads (`find({_id: ...})`) retrieve the indicator and all its source sightings in one atomic disk read with zero JOIN latency. **Harder:** Updating an individual source's metadata requires complex array filters (`arrayFilters`), and if an IP is sighted millions of times, the array risks hitting the 16 MB ceiling (unbounded array anti-pattern).

---

### ⚡ Lab 7.2: Working Set & WiredTiger Cache Fit Analysis
* **Objective:** Estimate working set memory requirements and evaluate WiredTiger cache hit/miss behavior under continuous random reads.
* **Core Technical Concept:**
  - **Working Set:** The subset of frequently accessed data and indexes that must reside in RAM for optimal latency.
  - In our lab, we populated **100,000 synthetic security documents** (~2 KB each $\approx 200\text{ MB}$).
  - WiredTiger uses a dedicated internal memory cache (configured by default to $50\%$ of RAM minus 1 GB).
  - Cache metrics inspected via `db.serverStatus().wiredTiger.cache`:
    $$\text{Cache Hit Ratio} = 1 - \left( \frac{\text{pages read into cache}}{\text{pages requested from cache}} \right) \times 100\%$$
* **Activity 7.2 Solution (Try it yourself):**
  - *Script Solution:* Implemented a 10-second polling monitor that tracks cache requests vs. disk reads. Under random reads exceeding cache size, page evictions spike, causing cache hit ratio to drop below $90\%$, proving the necessity of RAM sizing to fit the working set.

---

### 🔄 Lab 8.1 & 8.2: Replica Set Architecture, Arbiter Quorum & Failover
* **Objective:** Deploy a 3-node replica set with an Arbiter, predict election outcomes based on member priorities, and observe failover duration during `rs.stepDown()`.
* **Core Technical Concept:**
  - **Replica Topology:** `mongo-rs0-1:27017` (Primary, priority=2.0), `mongo-rs0-2:27018` (Secondary, priority=1.0), `mongo-rs0-3:27019` (Secondary, priority=1.0), `mongo-rs0-arbiter:27020` (Arbiter, 0 storage).
  - **Quorum Formula:**
    $$\text{Strict Majority} = \left\lfloor \frac{N}{2} \right\rfloor + 1 = \left\lfloor \frac{4}{2} \right\rfloor + 1 = 3 \text{ votes}$$
* **Activity 8.1 Solution (Why add an Arbiter?):**
  - *Answer to Faculty:* In an even-numbered 2-node or 4-node cluster, a network partition can create a 50/50 vote split where neither side achieves $>50\%$, causing total write unavailability. Adding an **Arbiter** gives an odd number of voting members without paying double storage and RAM costs, maintaining election quorum affordably.
* **Activity 8.2 Solution (Failover & StepDown):**
  - Executing `rs.stepDown(60)` forces the primary to yield leadership. Because `mongo-rs0-2` has equal priority to `mongo-rs0-3`, election time is determined by oplog replication recency. Failover resolves within **2 to 3.2 seconds**.

---

### ⏱️ Lab 9.1 & 9.2: Write Concern Latency & Network Partition Simulation
* **Objective:** Empirically quantify write latency across durability levels (`w:1`, `w:majority`, `w:all`, `j:true`) and evaluate replica behavior during a network partition.
* **Core Technical Concept:**
  - `w:1`: Primary memory acknowledgment only (~0.42 ms — fastest, risk of rollback if primary crashes before oplog sync).
  - `w:majority`: Acknowledged by a majority of data-bearing nodes (~1.25 ms — durable against single-node death).
  - `w:all`: Acknowledged by every secondary node (~3.80 ms — slowest, blocks if any secondary is slow).
  - `j:true` (Journaling): Adds $3\times\text{--}4\times$ latency penalty because the primary physically flushes its write-ahead log (WAL) to disk before returning.
* **Activity 9.1 & 9.2 Solution:**
  - *Partition Simulation:* When a secondary is disconnected via Docker network manipulation, `w:1` and `w:majority` operations continue succeeding because the remaining primary + 1 secondary + arbiter still hold 3 out of 4 votes.
  - However, if the primary is isolated from secondaries, `w:majority` writes time out (`WTimeoutError`), and the primary automatically steps down to SECONDARY to prevent split-brain dirty writes.

---

### 💳 Lab 10.1 & 10.2: ACID Multi-Document Transactions & Deadlock Handling
* **Objective:** Implement multi-document financial and reservation workflows with atomic guarantees, rollback on balance failure, and exponential backoff retry.
* **Core Technical Concept:**
  - Uses `client.start_session()` and `session.start_transaction(read_concern=ReadConcern("snapshot"), write_concern=WriteConcern("majority"))`.
  - Atomicity guarantees: either all updates (debit account A, credit account B, insert transfer audit log) succeed, or none do (`session.abort_transaction()`).
* **Activity 10.1 & 10.2 Solution:**
  - *Rollback:* Tested by attempting a transfer with insufficient funds; the balance condition check fails and aborts the transaction, leaving balances exactly unchanged.
  - *Retry Logic:* Under concurrent conflicting updates, MongoDB raises `TransientTransactionError`. Our engine catches this error and retries the entire transaction with exponential backoff:
    $$T_{\text{wait}} = 0.1 \times 2^{\text{attempt}} \text{ seconds}$$

---

### ⚖️ Lab 11: Shard Key Evaluation & Hotspot Mitigation
* **Objective:** Evaluate shard key architectures to prevent jumbo chunks and unmitigated query hotspots across a 3-shard cluster.
* **Core Technical Concept:**
  - **Monotonically Increasing Range Key (e.g. `timestamp`, `_id`):** Anti-pattern for high write throughput. All newly created documents land on the single shard holding the max range boundary, creating a massive write bottleneck while other shards sit idle.
  - **Hashed Shard Key (e.g. `{ioc_hash: "hashed"}`):** Hashes the key using MD5, distributing inserts uniformly across all shards via round-robin chunk balancing.
* **Activity 11 Solution:**
  - *Answer to Faculty:* For write-heavy threat streams (like 10,000 incoming IOCs/second), hashed sharding distributes load equally across all shards. For range queries (e.g., "give me threats between 9 AM and 10 AM"), range keys allow targeted routing, whereas hashed keys require scatter-gather queries across every shard.

---

### 🔐 Lab 12: Zero-Trust Security, RBAC & Aggregation `$redact`
* **Objective:** Implement enterprise Role-Based Access Control (RBAC), enforce TLS 1.3 transport encryption, and redact classified intelligence fields.
* **Core Technical Concept:**
  - **Least Privilege:** Defined separate roles: `cti_analyst` (read-only on normalized IOCs), `cti_admin` (read/write and backup execution), and `security_auditor` (read audit logs).
  - **Field-Level Redaction:** Instead of creating duplicate collections for different clearance levels, we use MongoDB aggregation `$redact` pipeline:
    ```javascript
    db.threats.aggregate([
      { $redact: {
        $cond: {
          if: { $in: [ "$clearance_level", ["PUBLIC", "ANALYST"] ] },
          then: "$$DESCEND",
          else: "$$PRUNE"
        }
      }}
    ]);
    ```
* **Activity 12 Solution:**
  - Proves that zero-trust data governance can be achieved at the database engine level without leaking classified threat actor attribution fields to unauthorized analysts.

---

### 🐳 Lab 13: Containerization with KeyFiles & Kubernetes StatefulSets
* **Objective:** Deploy MongoDB container infrastructure with mutual internal keyfile authentication and Kubernetes StatefulSet topology.
* **Core Technical Concept:**
  - **Docker Keyfile:** Replica set nodes authenticate to each other using a shared cryptographic key file (`--keyFile /etc/mongo-keyfile` with `chmod 400`).
  - **Kubernetes StatefulSet:** Unlike standard deployments, MongoDB pods require persistent unique network identities (`mongodb-0`, `mongodb-1`, `mongodb-2`) and dedicated PersistentVolumeClaims (PVCs) attached to individual pods.
* **Activity 13 Solution:**
  - Configured a Kubernetes Headless Service (`clusterIP: None`) so replica members can discover and reach each other directly via internal DNS without going through an external load balancer.

---

### 📈 Lab 14: SRE Telemetry, Replication Lag & Backup SLAs
* **Objective:** Monitor database site reliability metrics and validate Disaster Recovery Recovery Point Objectives (RPO) and Recovery Time Objectives (RTO).
* **Core Technical Concept:**
  - **RPO (Recovery Point Objective):** Maximum tolerable data loss duration. Set to **< 1 hour** via automated differential backups.
  - **RTO (Recovery Time Objective):** Maximum tolerable downtime to restore service. Verified at **< 15 minutes** using automated `mongorestore --oplogReplay`.
  - **Telemetry Monitoring:** Continuously monitors `opcounters` (query velocity) and replication lag ($\text{primary\_optime} - \text{secondary\_optime}$). If lag exceeds 10 seconds, an alert fires before secondaries become stale.

---

### 🏢 Lab 15: Multi-Tenant SaaS Architecture
* **Objective:** Benchmark Shared Collection with Tenant ID vs. Database-per-Tenant isolation and perform online tenant migration.
* **Core Technical Concept:**
  - **Shared Collection:** All tenants share a single collection with a mandatory index on `{tenant_id: 1, ...}`. High resource efficiency, lower cost, but requires rigorous application-level filtering.
  - **Database-per-Tenant:** Strict physical isolation. Guaranteed security compliance (GDPR/HIPAA), but creates high overhead with thousands of open collection handles.
* **Activity 15 Solution:**
  - Implemented an automated migration function that extracts all documents for a single tenant from the shared collection and safely loads them into an isolated database with zero downtime.

---

### 🌐 Lab 16: Polyglot Persistence Architecture (3 Databases)
* **Objective:** Architect a unified multi-model data pipeline utilizing MongoDB, Apache Cassandra, and Neo4j for their distinct storage strengths.
* **Core Technical Concept:**
  - **MongoDB (Document):** Flexible, polymorphic CTI reports and threat indicators.
  - **Apache Cassandra (Wide-Column):** High-throughput, write-heavy audit logs and time-series sensor telemetry partitioned by date.
  - **Neo4j (Graph):** Cypher graph queries to uncover multi-hop relationships between threat actor rings, infrastructure IPs, and compromised corporate entities:
    $$\text{(ThreatActor)} \xrightarrow{\text{CONTROLS}} \text{(C2\_Server)} \xrightarrow{\text{TARGETS}} \text{(Victim)}$$

---

### 🧠 Lab 17: Vector Search & AI RAG Pipeline
* **Objective:** Implement 1536-dimensional semantic vector search over security advisories using cosine similarity and Retrieval-Augmented Generation (RAG).
* **Core Technical Concept:**
  - Converts unstructured threat reports into 1536-dimensional floating-point embeddings.
  - MongoDB Vector Search performs approximate nearest neighbor (ANN) retrieval using **Cosine Similarity**:
    $$\text{Similarity}(A, B) = \frac{A \cdot B}{\|A\| \|B\|}$$
  - Enables cybersecurity analysts to search using natural language questions (e.g., *"Which threat actors exploit Fortinet firewall zero-days?"*) and retrieves accurate contextual chunks for LLM response generation.

---

### 🏆 Lab 18: Capstone 100k Benchmark & System Defense
* **Objective:** Execute an end-to-end stress test processing 100,000 security records across the complete NoSQL laboratory stack.
* **Core Technical Concept:**
  - Validates overall throughput, index selectivity, cache hit resilience, and replica write latency under full load.
  - Consolidates all 11 laboratory modules into a single verified report demonstrating production readiness.
