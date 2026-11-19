"""Database helpers for the MongoDB lab exercises."""

import os

from pymongo import MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")


def banner(title: str) -> None:
    """Print a simple section banner."""
    line = "=" * 80
    print(f"\n{line}\n{title}\n{line}\n")


def get_db(db_name: str):
    """Return a database handle connected to the local MongoDB instance."""
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    client.admin.command("ping")
    return client[db_name]


def reset_collection(db_name: str, collection_name: str):
    """Drop and recreate a collection in the given database."""
    db = get_db(db_name)
    if collection_name in db.list_collection_names():
        db[collection_name].drop()
    return db[collection_name]
