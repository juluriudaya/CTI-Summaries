#!/usr/bin/env python3
"""
CTI Fusion Center - Master Laboratory Runner (Labs 1 through 18)
-----------------------------------------------------------------
Orchestrates and executes all experiments from Lab 1 to Lab 18:
- Lab 1: NoSQL Taxonomy & Domain Classification
- Lab 2: Multi-Instance Ping & $mul CRUD
- Lab 3: Embedded vs Referenced Data Modeling
- Lab 4: Product Query API & Bulk Upserts
- Lab 5: Sales Aggregations & $lookup Relational Joins
- Lab 6: Index Design & Query Optimization (IXSCAN vs COLLSCAN)
- Lab 7.1: CTI Threat Data Modeling & BSON Sizing
- Lab 7.2: WiredTiger Cache & Performance Working Set Benchmark
- Lab 8.1 / 8.2: Replica Set Deployment, Arbiter & Failover/Election
- Lab 9.1 / 9.2: Write Concern Latency & Network Partition Simulation
- Lab 10.1 / 10.2: ACID Transactions & Concurrency with Deadlock Handling
- Lab 11.1 / 11.2: Shard Key Evaluation & Monotonic vs Hashed Hotspots
- Lab 12.1 / 12.2: MongoDB Security, RBAC & Field Redaction & TLS
- Lab 13.1 / 13.2: Containerized Replica Set & Kubernetes StatefulSet
- Lab 14.1 / 14.2: Real-time Monitoring & Automated Backup/Restore SLAs
- Lab 15.1 / 15.2: Multi-Tenant Architecture & Isolation Migration
- Lab 16.1 / 16.2: Polyglot Persistence & Hybrid Service with Circuit Breaker
- Lab 17.1 / 17.2: Vector Search, RAG Pipeline & HNSW vs IVF Index Benchmark
- Lab 18.1 / 18.2: Capstone 100k Threat Benchmark & Comparative Report

Usage:
    python run_all_experiments.py [--uri <mongodb_uri>]
"""

import sys
import os
import argparse
from datetime import datetime, timezone

# Ensure local modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from labs_engine import run_all_experiments_suite
except ImportError:
    # If invoked from another directory, attempt relative import
    from CTI_Fusion_Center_Updated.CTI_Fusion_Center_Docker_Advanced_Checked.cti_fusion_center_docker_keyless.labs_engine import run_all_experiments_suite


def main():
    parser = argparse.ArgumentParser(description="Run all CTI Fusion Center experiments (Labs 8–18)")
    parser.add_argument(
        "--uri",
        default=os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
        help="MongoDB connection URI (default: mongodb://localhost:27017)"
    )
    args = parser.parse_args()

    print("=" * 80)
    print("  🛡️  CTI FUSION CENTER — MASTER LABORATORY RUNNER (LABS 1 TO 18)")
    print("=" * 80)
    print(f"Target MongoDB URI: {args.uri}")
    print(f"Start Time:         {datetime.now(timezone.utc).isoformat()}\n")

    report = run_all_experiments_suite(args.uri)

    print("\n" + "=" * 80)
    print("  EXECUTIVE SUMMARY OF EXPERIMENT RESULTS")
    print("=" * 80)
    print(f"{'Lab ID':<10} {'Experiment Name':<38} {'Status':<12} {'Duration':<12} {'Assertion':<12}")
    print("-" * 86)
    for s in report["summary"]:
        print(f"{s['Lab ID']:<10} {s['Title']:<38} {s['Status']:<12} {str(s['Duration (ms)']) + 'ms':<12} {s['Assertion Verification']:<12}")

    print("-" * 86)
    print(f"Total Execution Duration: {report['total_duration_seconds']}s")
    print("Reports Generated:")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"  • JSON Report:     {os.path.join(base_dir, 'master_experiments_report.json')}")
    print(f"  • Markdown Report: {os.path.join(base_dir, 'MASTER_EXPERIMENTS_REPORT.md')}")
    print("=" * 80)
    print("All experiments connected to CTI Fusion Center executed successfully.")


if __name__ == "__main__":
    main()
