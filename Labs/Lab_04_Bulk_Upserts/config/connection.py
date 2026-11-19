"""MongoDB connection helpers for the lab exercises."""

from __future__ import annotations

from pymongo import MongoClient


def banner(title: str) -> None:
    print("=" * 80)
    print(title)
    print("=" * 80)


def get_db(db_name: str = "nosql_labs"):
    """Return a MongoDB database instance."""
    client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
    except Exception as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(
            "MongoDB is not running. Start MongoDB first, then run this script again."
        ) from exc
    return client[db_name]


def reset_collection(db_name: str, collection_name: str):
    """Get a collection and clear it before starting the lab."""
    db = get_db(db_name)
    collection = db[collection_name]
    collection.delete_many({})
    return collection
