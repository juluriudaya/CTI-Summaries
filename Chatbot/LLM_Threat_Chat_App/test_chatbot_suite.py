"""Comprehensive Automated Test Suite for CTI Chat Bot

Tests 20 Diverse Real-World Questions Across:
1. Real-world Platform Threat Modeling (Udemy, Byju's, Netflix, Stripe, Uber, Swiggy)
2. Website Threat Intelligence & Forensic URL Scans
3. Local Host System Cyber Vulnerability Diagnostics
4. Curriculum NoSQL Laboratory Experiments (Labs 1–18)
5. Software Engineering & Programming Queries
6. Real-World CVEs & Enterprise Cybersecurity
7. Typo-Heavy & Edge Cases
"""

import time
import requests
import json
import re

API_URL = "http://127.0.0.1:8005/chat"

TEST_CASES = [
    {
        "id": "TC-01",
        "category": "Platform Threat Model",
        "prompt": "give me the trat analysis of the udemey platform",
        "expected_entity": "udemy",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-02",
        "category": "Platform Threat Model",
        "prompt": "Give me the threat aanalysis of byju slarnin gplatform",
        "expected_entity": "byju",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-03",
        "category": "Platform Threat Model",
        "prompt": "Give me the threat analysis of Netflix streaming platform",
        "expected_entity": "netflix",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-04",
        "category": "Platform Threat Model",
        "prompt": "Give me the threat analysis of Stripe payment gateway",
        "expected_entity": "stripe",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-05",
        "category": "Platform Threat Model",
        "prompt": "Give me the threat analysis of Uber geospatial dispatch platform",
        "expected_entity": "uber",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-06",
        "category": "Platform Threat Model",
        "prompt": "threat of swiggy food delivery platform",
        "expected_entity": "swiggy",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-07",
        "category": "Forensic Website Scan",
        "prompt": "Analyze this website http://paypal-security-update.xyz/login/verify.php?token=123",
        "expected_entity": "paypal-security-update.xyz",
        "forbidden_terms": ["Lab 13"]
    },
    {
        "id": "TC-08",
        "category": "Forensic Website Scan",
        "prompt": "Is this website safe: https://www.google.com",
        "expected_entity": "google.com",
        "forbidden_terms": ["Lab 13"]
    },
    {
        "id": "TC-09",
        "category": "Local Host Diagnostics",
        "prompt": "Scan my system for cyber vulnerabilities",
        "expected_entity": "vulnerabilit",
        "forbidden_terms": ["Pegasus Spyware"]
    },
    {
        "id": "TC-10",
        "category": "Curriculum Lab",
        "prompt": "Explain Lab 7.2 WiredTiger cache and eviction mechanics",
        "expected_entity": "wiredtiger",
        "forbidden_terms": ["Pegasus Spyware"]
    },
    {
        "id": "TC-11",
        "category": "Curriculum Lab",
        "prompt": "What happened during the Lab 8 replica set failover experiment?",
        "expected_entity": "replica set",
        "forbidden_terms": ["Pegasus Spyware"]
    },
    {
        "id": "TC-12",
        "category": "Curriculum Lab",
        "prompt": "Explain Lab 10 multi-document ACID transactions and snapshot isolation",
        "expected_entity": "acid",
        "forbidden_terms": ["Pegasus Spyware"]
    },
    {
        "id": "TC-13",
        "category": "Curriculum Lab",
        "prompt": "How does horizontal sharding in Lab 11 prevent chunk hotspots?",
        "expected_entity": "sharding",
        "forbidden_terms": ["Pegasus Spyware"]
    },
    {
        "id": "TC-14",
        "category": "Curriculum Catalog",
        "prompt": "List all 18 labs in the curriculum",
        "expected_entity": "lab 1",
        "forbidden_terms": ["Pegasus Spyware"]
    },
    {
        "id": "TC-15",
        "category": "Software Engineering",
        "prompt": "Write a Python script to connect to MongoDB and perform bulk upserts",
        "expected_entity": "bulkwrite",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-16",
        "category": "Computer Science / DB",
        "prompt": "What is the difference between SQL and NoSQL databases with a comparison table?",
        "expected_entity": "nosql",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-17",
        "category": "Real-World CVE",
        "prompt": "How do attackers exploit Log4j CVE-2021-44228 and how do we mitigate it?",
        "expected_entity": "cve-2021-44228",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-18",
        "category": "Enterprise Security",
        "prompt": "Explain Zero-Trust Network Architecture (ZTNA) principles in enterprise cloud",
        "expected_entity": "zero-trust",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    },
    {
        "id": "TC-19",
        "category": "Typo Edge Case",
        "prompt": "wat is wiredtgr cach hit ratio",
        "expected_entity": "cache",
        "forbidden_terms": ["Pegasus Spyware"]
    },
    {
        "id": "TC-20",
        "category": "Cryptography",
        "prompt": "What is the difference between symmetric and asymmetric encryption?",
        "expected_entity": "encryption",
        "forbidden_terms": ["Lab 13", "Pegasus Spyware"]
    }
]

def run_test_suite():
    print("=" * 80, flush=True)
    print("🚀 STARTING CTI CHAT BOT COMPREHENSIVE AUTOMATED TEST SUITE (20 REAL-WORLD CASES)", flush=True)
    print(f"Target Endpoint: {API_URL}", flush=True)
    print("=" * 80, flush=True)

    results = []
    total_passed = 0

    for tc in TEST_CASES:
        tc_id = tc["id"]
        category = tc["category"]
        prompt = tc["prompt"]
        expected = tc["expected_entity"].lower()
        forbidden = [f.lower() for f in tc["forbidden_terms"]]

        print(f"\n[{tc_id}] Category: {category}", flush=True)
        print(f"  Prompt: \"{prompt}\"", flush=True)

        payload = {
            "message": prompt,
            "session_id": f"suite_{tc_id.lower()}",
            "platform": "all",
            "stage": "active"
        }

        start_time = time.time()
        try:
            resp = requests.post(API_URL, json=payload, timeout=45)
            latency = round((time.time() - start_time) * 1000, 1)

            if resp.status_code != 200:
                print(f"  ❌ FAILED: HTTP Status {resp.status_code}", flush=True)
                results.append({"id": tc_id, "status": "FAIL", "reason": f"HTTP {resp.status_code}", "latency": latency})
                continue

            data = resp.json()
            answer = data.get("answer", "")
            backend = data.get("backend", "Unknown")
            ans_lower = answer.lower()

            # Verification 1: Has Deep Thinking block
            has_deep_thinking = "<details open>" in answer or "<summary>" in answer or "deep thinking" in ans_lower
            
            # Verification 2: Expected entity present
            has_expected = expected in ans_lower
            
            # Verification 3: Forbidden spurious content absent
            found_forbidden = [f for f in forbidden if f in ans_lower]

            passed = (len(answer) > 100) and (not found_forbidden)

            if passed:
                total_passed += 1
                status_str = "✅ PASS"
            else:
                status_str = "⚠️ FAIL"

            print(f"  Status: {status_str} | Backend: `{backend}` | Latency: {latency}ms | Length: {len(answer)} chars", flush=True)
            print(f"  Deep Thinking: {'Yes' if has_deep_thinking else 'No'} | Expected '{expected}': {'Found' if has_expected else 'Missing'} | Spurious Content: {'None' if not found_forbidden else found_forbidden}", flush=True)
            print(f"  Preview: {answer[:180].replace(chr(10), ' ')}...", flush=True)

            results.append({
                "id": tc_id,
                "category": category,
                "prompt": prompt,
                "status": status_str,
                "backend": backend,
                "latency_ms": latency,
                "has_deep_thinking": has_deep_thinking,
                "has_expected": has_expected,
                "forbidden_found": found_forbidden,
                "answer_len": len(answer)
            })

        except Exception as e:
            latency = round((time.time() - start_time) * 1000, 1)
            print(f"  ❌ EXCEPTION: {e}", flush=True)
            results.append({"id": tc_id, "status": "EXCEPTION", "reason": str(e), "latency": latency})

    print("\n" + "=" * 80, flush=True)
    print(f"📊 TEST SUITE SUMMARY: {total_passed} / {len(TEST_CASES)} PASSED ({(total_passed / len(TEST_CASES)) * 100:.1f}%)", flush=True)
    print("=" * 80, flush=True)

    # Save results to json for detailed reporting
    with open("test_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_test_suite()
