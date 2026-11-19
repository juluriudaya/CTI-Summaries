"""Shared MongoDB helpers for Lab 17.1 and display helper for Lab 17.2."""

import os
from pymongo import MongoClient
from rich.console import Console
from rich.rule import Rule

_console = Console()
_client = None


def get_client():
    """Return a reusable MongoDB client.

    Defaults to the Lab 16 Docker MongoDB host port 27222.
    Override with the MONGO_URI environment variable when needed.
    """
    global _client
    if _client is None:
        uri = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27222")
        _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        _client.admin.command("ping")
    return _client


def get_db(name="nosql_labs"):
    return get_client()[name]


def reset_collection(db_name, collection_name):
    """Drop and recreate only the named lab collection."""
    db = get_db(db_name)
    if collection_name in db.list_collection_names():
        db.drop_collection(collection_name)
    return db[collection_name]


def banner(message):
    _console.print(Rule(f"[bold cyan]{message}[/bold cyan]"))


def close_client():
    global _client
    if _client is not None:
        _client.close()
        _client = None
