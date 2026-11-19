USE threat_intelligence;

CREATE TABLE IF NOT EXISTS threats_by_target (
    target text,
    event_date date,
    timestamp timestamp,
    threat_id text,
    source_id text,
    threat_type text,
    indicator text,
    confidence double,
    PRIMARY KEY ((target, event_date), timestamp, threat_id)
) WITH CLUSTERING ORDER BY (timestamp DESC);
