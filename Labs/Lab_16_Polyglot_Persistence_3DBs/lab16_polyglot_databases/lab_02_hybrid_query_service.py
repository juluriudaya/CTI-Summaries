
"""
LAB 16.2 - HYBRID QUERY SERVICE
Live integration with MongoDB, Cassandra and Neo4j.
"""

import os
from datetime import datetime, timedelta, timezone

from pymongo import MongoClient
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
from neo4j import GraphDatabase


# --------------------------------------------------
# DATABASE CONFIGURATION
# --------------------------------------------------

MONGO_URI = "mongodb://127.0.0.1:27222"
MONGO_DB = "lab16_fraud"

CASSANDRA_HOST = os.getenv("CASSANDRA_HOST", "127.0.0.1")
CASSANDRA_PORT = int(os.getenv("CASSANDRA_PORT", "9042"))

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD", "lab16StrongPassword"
)


# --------------------------------------------------
# SAMPLE DATA
# --------------------------------------------------

CASES = [
    {
        "case_id": "FC-001",
        "user_id": "U-101",
        "risk_score": 0.92,
        "status": "HIGH",
        "amount": 95000
    },
    {
        "case_id": "FC-002",
        "user_id": "U-102",
        "risk_score": 0.45,
        "status": "MEDIUM",
        "amount": 12000
    },
    {
        "case_id": "FC-003",
        "user_id": "U-103",
        "risk_score": 0.88,
        "status": "HIGH",
        "amount": 76000
    }
]

EVENTS = [
    ("U-101", "LOGIN", "Device-A"),
    ("U-101", "PAYMENT", "Device-B"),
    ("U-102", "LOGIN", "Device-A"),
    ("U-103", "TRANSFER", "Device-B"),
    ("U-104", "LOGIN", "Device-C"),
    ("U-105", "PAYMENT", "Device-B")
]

RELATIONSHIPS = [
    ("U-101", "Device-A"),
    ("U-102", "Device-A"),
    ("U-103", "Device-B"),
    ("U-101", "Device-B"),
    ("U-104", "Device-C"),
    ("U-105", "Device-B")
]


# --------------------------------------------------
# MONGODB SERVICE
# --------------------------------------------------

class MongoService:

    def __init__(self):
        self.client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000
        )

        self.client.admin.command("ping")

        self.db = self.client[MONGO_DB]
        self.cases = self.db["cases"]

    def seed_data(self):
        for case in CASES:
            self.cases.update_one(
                {"case_id": case["case_id"]},
                {"$set": case},
                upsert=True
            )

    def find_case(self, case_id):
        return self.cases.find_one(
            {"case_id": case_id},
            {"_id": 0}
        )

    def high_risk_cases(self):
        return list(
            self.cases.find(
                {"risk_score": {"$gte": 0.80}},
                {"_id": 0}
            )
        )

    def close(self):
        self.client.close()


# --------------------------------------------------
# CASSANDRA SERVICE
# --------------------------------------------------

class CassandraService:

    def __init__(self):
        self.cluster = Cluster(
            [CASSANDRA_HOST],
            port=CASSANDRA_PORT
        )

        self.session = self.cluster.connect()

        self.session.execute("""
            CREATE KEYSPACE IF NOT EXISTS lab16_fraud
            WITH replication = {
                'class': 'SimpleStrategy',
                'replication_factor': 1
            }
        """)

        self.session.set_keyspace("lab16_fraud")

        self.session.execute("""
            CREATE TABLE IF NOT EXISTS user_events (
                user_id TEXT,
                event_time TIMESTAMP,
                event_type TEXT,
                device_id TEXT,
                PRIMARY KEY (user_id, event_time)
            ) WITH CLUSTERING ORDER BY
            (event_time DESC)
        """)

    def seed_data(self):

        insert_query = self.session.prepare("""
            INSERT INTO user_events
            (user_id, event_time, event_type, device_id)
            VALUES (?, ?, ?, ?)
        """)

        for index, event in enumerate(EVENTS):
            user_id, event_type, device_id = event

            event_time = (
                datetime.now(timezone.utc)
                - timedelta(minutes=index)
            )

            self.session.execute(
                insert_query,
                (
                    user_id,
                    event_time,
                    event_type,
                    device_id
                )
            )

    def recent_events(self, user_id, limit=10):

        query = SimpleStatement("""
            SELECT user_id, event_time,
                   event_type, device_id
            FROM user_events
            WHERE user_id = %s
            LIMIT 10
        """)

        rows = self.session.execute(query, (user_id,))

        return [
            {
                "user_id": row.user_id,
                "event_time": row.event_time,
                "event_type": row.event_type,
                "device_id": row.device_id
            }
            for row in rows
        ]

    def close(self):
        self.cluster.shutdown()


# --------------------------------------------------
# NEO4J SERVICE
# --------------------------------------------------

class Neo4jService:

    def __init__(self):

        self.driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD)
        )

        self.driver.verify_connectivity()

    def seed_data(self):

        with self.driver.session() as session:

            session.run("""
                MATCH (n)
                DETACH DELETE n
            """)

            for user_id, device_id in RELATIONSHIPS:

                session.run("""
                    MERGE (u:User {user_id: $user_id})
                    MERGE (d:Device {device_id: $device_id})
                    MERGE (u)-[:USED]->(d)
                """,
                user_id=user_id,
                device_id=device_id)

    def connected_users(self, user_id):

        with self.driver.session() as session:

            result = session.run("""
                MATCH (u:User {user_id: $user_id})
                      -[:USED]->
                      (d:Device)
                      <-[:USED]-
                      (other:User)

                WHERE other.user_id <> $user_id

                RETURN DISTINCT other.user_id AS user_id
            """, user_id=user_id)

            return [
                record["user_id"]
                for record in result
            ]

    def close(self):
        self.driver.close()


# --------------------------------------------------
# HYBRID QUERY SERVICE
# --------------------------------------------------

class HybridQueryService:

    def __init__(self):

        print("\nConnecting to all databases...")

        self.mongo = MongoService()
        print("[SUCCESS] MongoDB connected")

        self.cassandra = CassandraService()
        print("[SUCCESS] Cassandra connected")

        self.neo4j = Neo4jService()
        print("[SUCCESS] Neo4j connected")

    def initialize(self):

        print("\nInitializing sample data...")

        self.mongo.seed_data()
        print("[SUCCESS] MongoDB cases inserted")

        self.cassandra.seed_data()
        print("[SUCCESS] Cassandra events inserted")

        self.neo4j.seed_data()
        print("[SUCCESS] Neo4j relationships created")

    def execute_queries(self):

        print("\n" + "=" * 55)
        print("1. MONGODB - CASE LOOKUP")
        print("=" * 55)

        case = self.mongo.find_case("FC-001")
        print(case)

        print("\nHIGH-RISK CASES:")

        for case in self.mongo.high_risk_cases():
            print(case)

        print("\n" + "=" * 55)
        print("2. CASSANDRA - USER EVENT HISTORY")
        print("=" * 55)

        events = self.cassandra.recent_events("U-101")

        for event in events:
            print(event)

        print("\n" + "=" * 55)
        print("3. NEO4J - CONNECTED USERS")
        print("=" * 55)

        users = self.neo4j.connected_users("U-101")

        print("Users connected to U-101 through shared devices:")

        for user in users:
            print(user)

        print("\n" + "=" * 55)
        print("ALL THREE DATABASE QUERIES COMPLETED")
        print("=" * 55)

    def close(self):

        self.mongo.close()
        self.cassandra.close()
        self.neo4j.close()


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():

    service = None

    try:

        service = HybridQueryService()

        service.initialize()

        service.execute_queries()

    except Exception as error:

        print("\n[ERROR]", error)
        raise

    finally:

        if service is not None:
            service.close()

        print("\nDatabase connections closed.")


if __name__ == "__main__":
    main()
