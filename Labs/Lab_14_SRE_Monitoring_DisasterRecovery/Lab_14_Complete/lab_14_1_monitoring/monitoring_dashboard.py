"""
Lab 14.1 - MongoDB Monitoring Dashboard
Collects serverStatus metrics every 30 seconds, prints a table, logs metrics,
and optionally sends webhook alerts (Slack/Discord-compatible JSON payload).
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import requests
from pymongo import MongoClient
from rich.console import Console
from rich.table import Table
from pymongo.errors import OperationFailure, PyMongoError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "metrics.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

console = Console()


def send_webhook_alert(message: str) -> None:
    """Send an optional alert to a Slack/Discord incoming webhook."""
    webhook_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return

    payload = {"text": message}  # accepted by Slack; Discord accepts content instead
    if "discord.com/api/webhooks" in webhook_url:
        payload = {"content": message}

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logging.info("Webhook alert delivered")
    except requests.RequestException as exc:
        logging.error("Webhook delivery failed: %s", exc)


def collect_metrics(client: MongoClient) -> dict:
    status = client.admin.command("serverStatus")
    connections = status.get("connections", {})
    opcounters = status.get("opcounters", {})
    wt_cache = status.get("wiredTiger", {}).get("cache", {})

    # WiredTiger page-cache hit ratio: page requests served from cache divided
    # by all page requests. These are cumulative counters since server start.
    pages_read = int(wt_cache.get("pages read into cache", 0) or 0)
    pages_requested = int(wt_cache.get("pages requested from the cache", 0) or 0)
    page_total = pages_read + pages_requested
    cache_hit_ratio = (
        pages_requested / page_total if page_total > 0 else None
    )

    metrics = {
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "connections_current": connections.get("current", 0),
        "connections_available": connections.get("available", 0),
        "opcounters": {
            "insert": opcounters.get("insert", 0),
            "query": opcounters.get("query", 0),
            "update": opcounters.get("update", 0),
            "delete": opcounters.get("delete", 0),
            "command": opcounters.get("command", 0),
        },
        "cache_bytes_in_use": wt_cache.get("bytes currently in the cache", 0),
        "cache_max_bytes": wt_cache.get("maximum bytes configured", 0),
        "cache_dirty_bytes": wt_cache.get("tracked dirty bytes in the cache", 0),
        "cache_pages_read": pages_read,
        "cache_pages_requested": pages_requested,
        "cache_hit_ratio": cache_hit_ratio,
        "replica_set": None,
        "replication_lag_seconds": {},
    }

    # Standalone MongoDB instances do not support replSetGetStatus.
    try:
        repl = client.admin.command("replSetGetStatus")
        members = repl.get("members", [])
        primary_dates = [
            m.get("optimeDate") for m in members
            if m.get("stateStr") == "PRIMARY" and m.get("optimeDate") is not None
        ]
        metrics["replica_set"] = repl.get("set")
        if primary_dates:
            primary_optime = primary_dates[0]
            for member in members:
                if member.get("stateStr") == "SECONDARY" and member.get("optimeDate") is not None:
                    lag = (primary_optime - member["optimeDate"]).total_seconds()
                    metrics["replication_lag_seconds"][member.get("name", "unknown")] = max(0.0, lag)
    except (OperationFailure, PyMongoError):
        pass

    return metrics


def render_table(metrics: dict) -> Table:
    table = Table(title="MongoDB Monitoring Dashboard", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Timestamp", metrics["timestamp"])
    table.add_row("Connections (current)", str(metrics["connections_current"]))
    table.add_row("Connections (available)", str(metrics["connections_available"]))

    for name, value in metrics["opcounters"].items():
        table.add_row(f"Opcounter: {name}", f"{value:,}")

    table.add_row("WiredTiger cache bytes in use", f'{metrics["cache_bytes_in_use"]:,}')
    table.add_row("WiredTiger cache max bytes", f'{metrics["cache_max_bytes"]:,}')
    table.add_row("WiredTiger dirty cache bytes", f'{metrics["cache_dirty_bytes"]:,}')
    ratio = metrics["cache_hit_ratio"]
    table.add_row("WiredTiger page-cache hit ratio", "N/A" if ratio is None else f"{ratio * 100:.2f}%")
    table.add_row("Replica set", metrics["replica_set"] or "Not a replica set")

    if metrics["replication_lag_seconds"]:
        for member, lag in metrics["replication_lag_seconds"].items():
            table.add_row(f"Replication lag: {member}", f"{lag:.2f} seconds")
    return table


def check_alerts(metrics: dict) -> list:
    alerts = []
    ratio = metrics["cache_hit_ratio"]
    if ratio is not None and ratio < 0.80:
        alerts.append(f"WARNING: WiredTiger page-cache hit ratio is {ratio * 100:.2f}% (below 80%).")

    for member, lag in metrics["replication_lag_seconds"].items():
        if lag > 10:
            alerts.append(f"WARNING: Replication lag on {member} is {lag:.2f} seconds (over 10 seconds).")
    return alerts


def main() -> None:
    uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    interval = int(os.getenv("MONITOR_INTERVAL_SECONDS", "30"))
    if interval < 1:
        raise ValueError("MONITOR_INTERVAL_SECONDS must be at least 1.")

    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
        console.print("[green]Connected to MongoDB. Monitoring every 30 seconds (Ctrl+C to stop).[/green]")
        while True:
            try:
                metrics = collect_metrics(client)
                console.clear()
                console.print(render_table(metrics))
                logging.info(json.dumps(metrics, default=str))

                for alert in check_alerts(metrics):
                    console.print(f"[bold red]{alert}[/bold red]")
                    logging.warning(alert)
                    send_webhook_alert(alert)

            except PyMongoError as exc:
                message = f"WARNING: MongoDB metrics collection failed: {exc}"
                console.print(f"[bold red]{message}[/bold red]")
                logging.exception(message)
                send_webhook_alert(message)

            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped by user.[/yellow]")
    finally:
        client.close()
        console.print(f"Metrics log: {LOG_FILE}")


if __name__ == "__main__":
    main()
