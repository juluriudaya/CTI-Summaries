import os
from pymongo import MongoClient
from pymongo.errors import PyMongoError

uri = os.environ.get("MONGO_URI")
if not uri:
    raise SystemExit("Set MONGO_URI before running this test.")
try:
    with MongoClient(uri, serverSelectionTimeoutMS=10000) as client:
        print("Ping:", client.admin.command("ping"))
        status = client.admin.command("replSetGetStatus")
        print("Replica set:", status["set"])
        for member in status["members"]:
            print(f"{member['name']}: {member['stateStr']} (health={member['health']})")
except PyMongoError as exc:
    raise SystemExit(f"Connection test failed: {exc}")
