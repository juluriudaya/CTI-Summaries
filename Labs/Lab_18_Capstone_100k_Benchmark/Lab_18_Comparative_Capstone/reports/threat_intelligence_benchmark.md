# Lab 18: Threat Intelligence Comparative Benchmark

- Records generated: 100,000
- Query repetitions: 10
- Write benchmark: 10 runs of 1,000 records per database
- Query metric: median latency in milliseconds
- Write metric: median batch latency and records per second
- All three databases use dedicated local instances

## Data ingestion time

| Database | Ingestion time (seconds) |
|---|---:|
| MongoDB | 1.831 |
| Cassandra | 87.131 |
| Neo4j | 67.381 |

## Query performance (median milliseconds)

| Database | Query | Median latency (ms) |
|---|---|---:|
| MongoDB | Threat history by source | 9.861 |
| MongoDB | Target and spread lookup | 3.636 |
| MongoDB | Daily/type volume lookup | 42.533 |
| Cassandra | Threat history by source | 15.697 |
| Cassandra | Target and spread lookup | 15.510 |
| Cassandra | Daily/type volume lookup | 90.486 |
| Neo4j | Threat history by source | 20.293 |
| Neo4j | Target and spread lookup | 31.611 |
| Neo4j | Daily/type volume lookup | 54.902 |

## Write throughput

| Database | Median batch latency (ms) | Records per second |
|---|---:|---:|
| MongoDB | 16.421 | 60,898.56 |
| Cassandra | 243.378 | 4,108.83 |
| Neo4j | 74.701 | 13,386.68 |

## False-positive analysis

False-positive labels are synthetically generated for this experiment. They are analyzed separately and are not used as a database performance query.

## Methodology and limitations

The experiment uses synthetic threat records and local database instances. Cassandra daily volume analytics uses five partition queries and counts the returned rows in Python because Cassandra does not provide the same general-purpose aggregation model as MongoDB. Query timings therefore include different database execution paths. Write throughput measures batches of 1,000 records over 10 runs. Results describe this local setup and should not be treated as production cluster performance.
