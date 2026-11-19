# Dictionary of tailored most common questions for Labs 1 to 18
LAB_COMMON_QUESTIONS = {
    "Lab 1": [
        "What are the 4 primary NoSQL database models classified in Lab 1?",
        "Explain the CAP theorem trade-offs between MongoDB and Cassandra in Lab 1.",
        "What classification heuristics were used to categorize the 10 database products?"
    ],
    "Lab 2": [
        "How does MongoDB execute in-place atomic updates using the $mul operator?",
        "What were the network latency differences between the local Docker container and Atlas?",
        "Why is in-place document manipulation faster than fetch-and-replace in Lab 2?"
    ],
    "Lab 3": [
        "When should you choose embedded schema modeling over referenced modeling in Lab 3?",
        "How did Lab 3 achieve a 7.5x faster single-read latency with embedded documents?",
        "How does normalized referencing prevent unbounded array growth in MongoDB?"
    ],
    "Lab 4": [
        "What is the difference between ordered and unordered bulkWrite in MongoDB?",
        "How do compound filter operators ($and, $or, $in) optimize product catalog searches in Lab 4?",
        "How does bulk upserting prevent duplicate document creation under concurrency?"
    ],
    "Lab 5": [
        "How does the aggregation pipeline process multi-stage sales data ($match, $group, $sort) in Lab 5?",
        "How does MongoDB perform relational left-outer joins using the $lookup stage?",
        "What is the performance overhead of $lookup joins compared to embedded queries?"
    ],
    "Lab 6": [
        "Explain the Equality, Sort, Range (ESR) rule for compound index design in Lab 6.",
        "How did the compound B-Tree index reduce scan execution time by 222x in Lab 6?",
        "What is the difference between IXSCAN and COLLSCAN in MongoDB executionStats?"
    ],
    "Lab 7.1": [
        "How does denormalized CTI data modeling stay within the 16MB BSON size limit?",
        "How does sub-document nesting enable sub-2ms correlation across millions of threat indicators?",
        "What schema design pattern prevents unbounded growth in threat indicator lists?"
    ],
    "Lab 7.2": [
        "What determines the 99.9% cache hit ratio in the WiredTiger storage engine in Lab 7.2?",
        "How do background eviction threads handle dirty pages when cache usage reaches 80%?",
        "How does RAM sizing impact MongoDB p99 read latencies under heavy ingestion?"
    ],
    "Lab 8": [
        "How does the Raft-like election protocol achieve majority quorum in a 3-node replica set in Lab 8?",
        "What happened during the rs.stepDown() failover test in Lab 8?",
        "What is the exact purpose of an Arbiter node in a MongoDB replica set?"
    ],
    "Lab 9": [
        "What is the difference between w:1 and w:majority write concerns in Lab 9?",
        "How does write concern prevent split-brain data loss during network partitions?",
        "What is the latency trade-off between strict consistency and write throughput?"
    ],
    "Lab 10": [
        "How does MongoDB implement two-phase commit and snapshot isolation in transactions (Lab 10)?",
        "What happened during the rollback test when account balance was insufficient?",
        "How does write conflict retry backoff prevent database deadlocks in Lab 10?"
    ],
    "Lab 11": [
        "Why do monotonically increasing shard keys create write bottlenecks (hotspots) in Lab 11?",
        "How does hashed sharding ensure even chunk distribution across replica shards?",
        "What is the role of mongos query routers and config servers in a sharded cluster?"
    ],
    "Lab 12": [
        "How does MongoDB enforce role-based access control (RBAC) with least privilege in Lab 12?",
        "What is the role of mutual TLS 1.3 encryption and SCRAM-SHA-256 authentication?",
        "How does the $redact aggregation stage enforce field-level data privacy?"
    ],
    "Lab 13": [
        "Why are Kubernetes StatefulSets used instead of Deployments for MongoDB replica sets in Lab 13?",
        "How do internal keyfiles authenticate inter-node replica set traffic in Docker?",
        "How does headless DNS provide stable network identities for database pods?"
    ],
    "Lab 14": [
        "What are the recovery point objective (RPO) and recovery time objective (RTO) achieved in Lab 14?",
        "How does mongodump and oplog replay enable point-in-time database restoration?",
        "What metrics in Full Time Diagnostic Data Capture (FTDC) signal storage bottlenecks?"
    ],
    "Lab 15": [
        "What are the trade-offs between database-per-tenant and shared-collection isolation in Lab 15?",
        "How is an online tenant migrated from a shared collection to a dedicated database without downtime?",
        "How does tenant ID indexing prevent cross-tenant data leakage in multi-tenant SaaS?"
    ],
    "Lab 16": [
        "How does the unified query service route workloads between MongoDB, Cassandra, and Neo4j in Lab 16?",
        "Why is Cassandra preferred for high-velocity time-series threat metrics over MongoDB?",
        "How does the circuit breaker pattern maintain application resilience when one database is down?"
    ],
    "Lab 17": [
        "How does Hierarchical Navigable Small World (HNSW) indexing accelerate vector cosine search in Lab 17?",
        "How are threat embeddings retrieved and injected into the LLM prompt context?",
        "What is the recall and latency difference between HNSW and IVF vector indexes?"
    ],
    "Lab 18": [
        "What were the throughput (ops/sec) and p99 latency results in the 100k capstone benchmark (Lab 18)?",
        "How did connection pooling and compound indexes sustain 48,000+ operations/second?",
        "How does the master audit suite synthesize verification assertions across all 18 labs?"
    ]
}
