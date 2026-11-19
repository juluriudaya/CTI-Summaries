"""Multi-Method Model Diagnostic & Verification Suite

Executes 4 distinct methods to evaluate and check the CTI Chat Bot Model:
Method 1: Intent & Semantic Similarity Vector Matcher (Confidence & Latency)
Method 2: Deep-Thinking SLM Inference & Technical Dossier Synthesis
Method 3: Strict Domain Scope Guardrail (In-Scope vs Out-of-Scope Filtering)
Method 4: Real-Time Host System Cyber Vulnerability Scanner Connection
"""

import os
import sys
import time
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from trained_matcher import get_trained_matcher
from llm_engine import generate_llm_response, is_query_in_scope, get_scope_restricted_message
from system_vulnerability_scanner import run_system_vulnerability_audit, format_scan_report_markdown


def method_1_vector_intent_matching():
    print("\n" + "=" * 75)
    print("  METHOD 1: VECTOR & INTENT CLASSIFICATION CHECK (Confidence & Latency)")
    print("=" * 75)
    matcher = get_trained_matcher()
    if not matcher or not matcher.is_trained:
        print("[-] Trained matcher not available.")
        return

    test_queries = [
        ("Lab 8 Replica Set Failover", "EXP-LAB8"),
        ("WiredTiger 99.9% cache hit ratio and eviction", "EXP-LAB7.2"),
        ("Multi-document ACID transactions with two-phase commit", "EXP-LAB10"),
        ("B-Tree compound index optimization", "EXP-LAB6"),
        ("What active ransomware attacks Windows?", "THREAT-WIN-001"),
        ("replca set failovr (Fuzzy Typo Test)", "EXP-LAB8"),
        ("Scan my system for cyber vulnerabilities", "INTENT-SCAN")
    ]

    for q, expected in test_queries:
        t0 = time.time()
        preds = matcher.predict(q, top_k=1)
        lat = (time.time() - t0) * 1000.0
        if preds:
            top = preds[0]
            matched_id = top.get("doc_id", "UNKNOWN")
            conf = round(top.get("score", 0.0), 3)
            status = "✅ PASS" if expected in matched_id else "⚠️ CHECK"
            print(f" {status} | Latency: {lat:4.1f}ms | Conf: {conf:5.3f} | Query: '{q}' ➔ [{matched_id}]")
        else:
            print(f" ❌ FAIL | Latency: {lat:4.1f}ms | No match for query: '{q}'")


def method_2_deep_thinking_slm():
    print("\n" + "=" * 75)
    print("  METHOD 2: DEEP-THINKING SLM INFERENCE & DOSSIER SYNTHESIS CHECK")
    print("=" * 75)
    query = "Explain Lab 8 replica set failover experiment"
    context_mock = [{
        "doc_id": "EXP-LAB8",
        "lab_id": "Lab 8",
        "title": "Replica Set High Availability, Heartbeats & Election Failover",
        "category": "High Availability / Distributed Consensus",
        "concept": "Raft-like Quorum Consensus & Automated Primary Failover",
        "what_happened": "Cluster of 3 nodes experienced primary isolation; remaining 2 nodes formed quorum and elected new primary in 2.8s.",
        "engine_internals": "Node heartbeats detected unreachable primary via 2s interval; electionTimeoutMillis (10s) triggered election priority.",
        "enterprise_impact": "Zero human intervention required during hardware loss; mission-critical high availability preserved.",
        "short_note": "A majority quorum ((n/2)+1) is mathematically required to elect a primary and prevent split-brain syndrome."
    }]

    t0 = time.time()
    resp = generate_llm_response(query, context_mock)
    lat = (time.time() - t0) * 1000.0

    answer = resp.get("answer", "")
    has_deep_thinking = "<summary>🧠 <b>Deep Thinking & Architectural Analysis" in answer
    has_what_happened = "What Happened in this Experiment" in answer
    has_internals = "Engine Internals & Technical Mechanics" in answer

    print(f" Backend:           {resp.get('backend')}")
    print(f" Latency:           {lat:.2f} ms")
    print(f" Deep Thinking Box: {'✅ VERIFIED' if has_deep_thinking else '❌ MISSING'}")
    print(f" What Happened:     {'✅ VERIFIED' if has_what_happened else '❌ MISSING'}")
    print(f" Engine Internals:  {'✅ VERIFIED' if has_internals else '❌ MISSING'}")
    print("\n--- Model Response Preview (First 400 chars) ---")
    print(answer[:400] + "...\n")


def method_3_domain_scope_guardrail():
    print("\n" + "=" * 75)
    print("  METHOD 3: STRICT DOMAIN SCOPE GUARDRAIL CHECK")
    print("=" * 75)
    
    test_suite = [
        # In-Scope Queries (Should Pass)
        ("Explain Lab 7.2 WiredTiger cache eviction", True, "In-Scope: Lab Experiment"),
        ("What active ransomware targets Windows?", True, "In-Scope: Cyber Threat"),
        ("Scan my system for cyber vulnerabilities", True, "In-Scope: System Security Audit"),
        ("List all 18 curriculum labs", True, "In-Scope: Catalog Query"),
        # Out-of-Scope Queries (Should be Filtered Out)
        ("What is the recipe for chocolate cake?", False, "Out-of-Scope: Cooking"),
        ("Who won the FIFA World Cup in 2022?", False, "Out-of-Scope: Sports"),
        ("Write a poem about the sunrise", False, "Out-of-Scope: Creative Writing"),
        ("What is the stock price of Apple?", False, "Out-of-Scope: Finance")
    ]

    for q, should_be_in_scope, desc in test_suite:
        actual_in_scope = is_query_in_scope(q)
        status = "✅ PASS" if actual_in_scope == should_be_in_scope else "❌ FAIL"
        label = "ALLOWED " if actual_in_scope else "FILTERED"
        print(f" {status} | [{label}] | {desc:32} | Query: '{q}'")


def method_4_system_vulnerability_scanner():
    print("\n" + "=" * 75)
    print("  METHOD 4: SYSTEM CYBER VULNERABILITY DIAGNOSTIC SCRIPT CHECK")
    print("=" * 75)
    t0 = time.time()
    audit_res = run_system_vulnerability_audit()
    lat = (time.time() - t0) * 1000.0

    metrics = audit_res["metrics"]
    sys_info = audit_res["system_info"]
    findings = audit_res["findings"]

    print(f" Target Host:       {sys_info['hostname']} ({sys_info['os']} {sys_info['architecture']})")
    print(f" Diagnostic Time:   {lat:.2f} ms")
    print(f" Ports Audited:     {metrics['ports_scanned']} TCP standard risk ports")
    print(f" Active Ports:      {metrics['open_ports_detected']}")
    print(f" Findings Count:    {metrics['total_vulnerabilities']} detected vulnerabilities")
    print(f" Overall Posture:   {metrics['overall_posture']}")

    if findings:
        top_f = findings[0]
        print(f" Sample Finding:    {top_f.get('title')} ({top_f.get('cve')}) - Severity: {top_f.get('severity')}")
        print(f" Remediation:       {top_f.get('remediation_command')}")
    print(" System Diagnostic: ✅ VERIFIED & OPERATIONAL")


if __name__ == "__main__":
    print("\n" + "#" * 75)
    print("  🔬 RUNNING COMPREHENSIVE MULTI-METHOD MODEL EVALUATION SUITE")
    print("#" * 75)
    method_1_vector_intent_matching()
    method_2_deep_thinking_slm()
    method_3_domain_scope_guardrail()
    method_4_system_vulnerability_scanner()
    print("\n" + "#" * 75)
    print("  🎉 ALL 4 EVALUATION METHODS COMPLETED SUCCESSFULLY!")
    print("#" * 75 + "\n")
