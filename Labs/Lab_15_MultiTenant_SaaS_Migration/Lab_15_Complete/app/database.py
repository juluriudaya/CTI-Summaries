import os
from pymongo import MongoClient, ASCENDING, DESCENDING
from dotenv import load_dotenv

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27221")
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client["lab15_saas"]

def initialize_indexes():
    db.tasks.create_index([("tenant_id", ASCENDING), ("created_at", DESCENDING)])
    db.tasks.create_index([("tenant_id", ASCENDING), ("owner_id", ASCENDING), ("created_at", DESCENDING)])
    db.users.create_index([("tenant_id", ASCENDING), ("username", ASCENDING)], unique=True)
    db.rate_limits.create_index("expires_at", expireAfterSeconds=0)
