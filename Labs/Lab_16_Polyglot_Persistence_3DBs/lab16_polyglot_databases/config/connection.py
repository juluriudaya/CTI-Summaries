"""Shared MongoDB connection helpers for Lab 16."""
import os
from pymongo import MongoClient

_client = None

def get_client():
    global _client
    if _client is None:
        uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Fail early with a useful connection error if MongoDB is unavailable.
        _client.admin.command("ping")
    return _client

def get_db(name="nosql_labs"):
    return get_client()[name]

def reset_collection(database_name, collection_name):
    db = get_db(database_name)
    if collection_name in db.list_collection_names():
        db[collection_name].drop()
    return db[collection_name]

def banner(message):
    line = "=" * 72
    print(f"\\n{line}\\n{message}\\n{line}")
