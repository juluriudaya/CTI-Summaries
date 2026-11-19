CREATE CONSTRAINT source_id_unique IF NOT EXISTS
FOR (s:Source)
REQUIRE s.source_id IS UNIQUE;

CREATE CONSTRAINT threat_id_unique IF NOT EXISTS
FOR (t:Threat)
REQUIRE t.threat_id IS UNIQUE;

CREATE INDEX threat_indicator_index IF NOT EXISTS
FOR (t:Threat)
ON (t.indicator);

CREATE INDEX threat_type_index IF NOT EXISTS
FOR (t:Threat)
ON (t.threat_type);
