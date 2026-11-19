-- Reference schema for Lab 18 comparative design.
-- Execute against a Cassandra keyspace created for this lab.

CREATE KEYSPACE IF NOT EXISTS lab18
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

USE lab18;

-- Query-driven table: threat / transaction history by source.
CREATE TABLE IF NOT EXISTS threats_by_source (
    source_id text,
    event_time timestamp,
    event_id text,
    threat_type text,
    target_id text,
    risk_score double,
    details text,
    PRIMARY KEY ((source_id), event_time, event_id)
) WITH CLUSTERING ORDER BY (event_time DESC);

-- Query-driven table: threats grouped by type and time.
CREATE TABLE IF NOT EXISTS threats_by_type (
    threat_type text,
    event_time timestamp,
    event_id text,
    source_id text,
    target_id text,
    risk_score double,
    details text,
    PRIMARY KEY ((threat_type), event_time, event_id)
) WITH CLUSTERING ORDER BY (event_time DESC);

-- Denormalize each event into both tables from the application.
