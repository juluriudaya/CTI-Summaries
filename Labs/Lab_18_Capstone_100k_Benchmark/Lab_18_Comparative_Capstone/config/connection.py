"""MongoDB connection helpers for Lab 18.

Uses a dedicated Lab 18 MongoDB port (27223) so it does not interfere
with the user's existing Lab 16 MongoDB container on port 27222.
"""
import os
from pymongo import MongoClient
from rich.console import Console
from rich.rule import Rule

_client = None
_console = Console()

def get_client():
    global _client
    if _client is None:
        uri = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27223")
        timeout = int(os.getenv("MONGO_TIMEOUT_MS", "5000"))
        _client = MongoClient(uri, serverSelectionTimeoutMS=timeout)
        _client.admin.command("ping")
    return _client

def get_db(name="capstone"):
    return get_client()[name]

def reset_collection(db_name, collection_name):
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
