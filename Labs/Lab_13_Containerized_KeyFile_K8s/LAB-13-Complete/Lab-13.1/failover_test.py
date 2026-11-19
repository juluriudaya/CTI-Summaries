import os, time
from pymongo import MongoClient
from pymongo.errors import PyMongoError

uri = os.environ.get("MONGO_URI")
if not uri:
    raise SystemExit("Set MONGO_URI before running this test.")
client = MongoClient(uri, serverSelectionTimeoutMS=8000, retryWrites=True)
collection = client["lab13"]["failover_events"]
print("Writing every 2 seconds. Step down the current primary from another terminal.")
try:
    for i in range(300):
        try:
            result = collection.insert_one({"sequence": i, "created_at": time.time()})
            print(f"Write {i}: OK ({result.inserted_id})")
        except PyMongoError as exc:
            print(f"Temporary election/connection error: {exc}")
        time.sleep(2)
finally:
    client.close()
