// Reference schema for Lab 18 comparative design.
CREATE CONSTRAINT source_id IF NOT EXISTS
FOR (s:Source) REQUIRE s.source_id IS UNIQUE;

CREATE CONSTRAINT threat_id IF NOT EXISTS
FOR (t:Threat) REQUIRE t.event_id IS UNIQUE;

// Example relationship creation:
// MERGE (s:Source {source_id: $source_id})
// MERGE (t:Threat {event_id: $event_id})
// SET t.threat_type = $threat_type,
//     t.target_id = $target_id,
//     t.event_time = datetime($event_time),
//     t.risk_score = $risk_score
// MERGE (s)-[:REPORTED]->(t);

// Example suspicious source-to-source relationship:
// MATCH (s1:Source)-[:REPORTED]->(t1:Threat),
//       (s2:Source)-[:REPORTED]->(t2:Threat)
// WHERE s1 <> s2
//   AND t1.target_id = t2.target_id
//   AND t1.threat_type = t2.threat_type
// MERGE (s1)-[:SUSPICIOUS]->(s2);
