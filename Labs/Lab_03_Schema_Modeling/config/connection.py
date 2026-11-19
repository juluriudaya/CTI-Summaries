"""Shared MongoDB connection and display helpers for the lab exercises."""

import json
import os

from pymongo import MongoClient


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)


def get_db(name):
    """Return a database handle using the shared MongoDB client."""
    return _client[name]


def reset_collection(database_name, collection_name):
    """Drop and recreate a collection, returning the empty collection handle."""
    database = get_db(database_name)
    if collection_name in database.list_collection_names():
        database.drop_collection(collection_name)
    return database[collection_name]


def banner(text):
    """Print a consistent section banner."""
    print(f"\n{'=' * 60}\n{text}\n{'=' * 60}")


def print_json(value):
    """Print a MongoDB document as indented JSON."""
    print(json.dumps(value, indent=2, default=str))