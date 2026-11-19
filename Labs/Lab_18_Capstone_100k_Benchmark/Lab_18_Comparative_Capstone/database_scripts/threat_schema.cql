CREATE KEYSPACE IF NOT EXISTS threat_intelligence
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

USE threat_intelligence;

CREATE TABLE IF NOT EXISTS threats_by_source (
    source_id text,
    event_date date,
    timestamp timestamp,
    threat_id text,
    threat_type text,
    indicator text,
    target text,
    confidence double,
    PRIMARY KEY ((source_id, event_date), timestamp, threat_id)
) WITH CLUSTERING ORDER BY (timestamp DESC);

CREATE TABLE IF NOT EXISTS threats_by_type (
    threat_type text,
    event_date date,
    timestamp timestamp,
    threat_id text,
    source_id text,
    indicator text,
    target text,
    confidence double,
    PRIMARY KEY ((threat_type, event_date), timestamp, threat_id)
) WITH CLUSTERING ORDER BY (timestamp DESC);
