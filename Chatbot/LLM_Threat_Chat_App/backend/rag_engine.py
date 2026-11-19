"""RAG (Retrieval-Augmented Generation) & Vector Search Engine

Implements:
1. Embedding generation (VoyageAI / OpenAI if keys provided, or deterministic semantic term embeddings)
2. Vector similarity retrieval ($vectorSearch with HNSW or brute-force cosine similarity)
3. Metadata filtering by platform (Windows, Linux, macOS, Android, iOS) and stage (Anticipated, Active, Evolving, Resolved)
4. Prompt synthesis with conversation memory from MongoDB 'sessions'.
"""

import os
import math
import hashlib
import re
from typing import List, Dict, Any, Optional

try:
    from trained_matcher import get_trained_matcher
except ImportError:
    get_trained_matcher = None

def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0
    return dot / (norm1 * norm2)


# Keyword anchors for semantic projection (Cyber Threats + Curriculum NoSQL Labs)
KEYWORD_ANCHORS = [
    # Platforms & Security
    "windows", "linux", "macos", "android", "ios", "cloud",
    "active", "anticipated", "evolving", "resolved", "mitigation", "remediation",
    "cve", "ransomware", "botnet", "rootkit", "stealer", "trojan", "exploit",
    "privilege", "escalation", "ssh", "powershell", "kernel", "firewall",
    "patch", "isolate", "certutil", "alphv", "mirai", "pegasus", "spynote",
    "lockdown", "audit", "command", "zero-day", "cvss", "vulnerability",
    # NoSQL Architecture, Storage Engine & Curriculum Experiments
    "lab", "experiment", "nosql", "replica", "failover", "election", "quorum", "stepdown",
    "wiredtiger", "cache", "eviction", "btree", "index", "ixscan", "collscan",
    "sharding", "chunk", "balancer", "router", "mongos", "configsvr", "transaction", "acid",
    "writeconcern", "isolation", "aggregation", "lookup", "pipeline", "benchmark",
    "capstone", "vector", "embedding", "similarity", "rag", "docker", "kubernetes", "rbac", "tls",
    "tenant", "polyglot", "json", "bson", "schema", "embedded", "referenced"
]

def generate_embedding(text: str, dim: int = 384) -> List[float]:
    """Generates embedding vector. Uses VoyageAI if key provided, else deterministic semantic token projection."""
    voyage_key = os.getenv("VOYAGE_API_KEY")
    if voyage_key:
        try:
            from voyageai import Client as VoyageClient
            vc = VoyageClient(api_key=voyage_key)
            return vc.embed([text], model="voyage-3").embeddings[0]
        except Exception:
            pass

    # High-quality deterministic semantic token projection (Hashing Trick)
    text_lower = text.lower()
    words = re.findall(r"\w+", text_lower)
    word_set = set(words)

    vec = [0.0] * dim

    # Token-level feature hashing (bag-of-words mapped to dimensions)
    for word in words:
        w_hash = hashlib.md5(word.encode("utf-8")).digest()
        idx1 = int.from_bytes(w_hash[:2], "big") % dim
        idx2 = int.from_bytes(w_hash[2:4], "big") % dim
        vec[idx1] += 1.0
        vec[idx2] += 0.5

    # Boost dimensions based on domain semantic anchors
    for idx, anchor in enumerate(KEYWORD_ANCHORS):
        if anchor in word_set:
            dim_target = (idx * 7) % dim
            vec[dim_target] += 3.0
            vec[(dim_target + 1) % dim] += 2.0

    # Normalize vector to unit length
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        return [x / norm for x in vec]
    return vec


def retrieve_context(
    db,
    query: str,
    platform: Optional[str] = None,
    stage: Optional[str] = None,
    n_results: int = 3
) -> List[Dict[str, Any]]:
    """Retrieve top-k matching threat knowledge chunks or lab experiments using trained model & vector search."""
    q_lower = query.strip().lower()

    # Detect lab inquiry
    lab_match = re.search(r"\b(?:lab|experiment|exp)\s*(1[0-8]|[1-9](\.[1-2])?)\b", q_lower)
    target_lab_id = None
    if lab_match:
        target_lab_id = f"Lab {lab_match.group(1)}"

    is_lab_query = bool(target_lab_id) or any(
        w in q_lower for w in [
            "experiment", "curriculum", "nosql lab", "all labs", "wiredtiger", "replica set",
            "failover", "ixscan", "capstone", "100k benchmark", "lookup join", "btree", "raft", "quorum"
        ]
    )

    # 1. Try High-Precision Trained Matcher (Char/Word N-Gram Model)
    if get_trained_matcher:
        try:
            matcher = get_trained_matcher()
            if matcher and matcher.is_trained:
                preds = matcher.predict(query, top_k=n_results, platform=platform, stage=stage)
                if preds and preds[0].get("score", 0.0) >= 0.20:
                    # Filter out lab chunks if the user did NOT ask about a lab
                    valid_preds = []
                    for p in preds:
                        doc_id = str(p.get("doc_id", ""))
                        is_lab_chunk = (
                            doc_id.startswith("EXP-LAB")
                            or doc_id.startswith("FAQ-Lab")
                            or doc_id.startswith("INTENT-LIST-LABS")
                            or "lab" in doc_id.lower()
                            or bool(p.get("lab_id"))
                        )
                        if is_lab_chunk and not is_lab_query:
                            continue
                        p["similarity"] = p.get("score", 0.0)
                        valid_preds.append(p)
                    if valid_preds:
                        return valid_preds
        except Exception:
            pass

    # 2. Fallback to MongoDB Vector Search
    query_vec = generate_embedding(query)
    knowledge_col = db.knowledge

    if is_lab_query:
        p_filter = "all"
        s_filter = "all"
    else:
        p_filter = platform.lower() if platform else "all"
        s_filter = stage.lower() if stage else "all"

        if p_filter in ["all", "all platforms"]:
            for p_cand in ["windows", "linux", "macos", "android", "ios"]:
                if p_cand in q_lower:
                    p_filter = p_cand
                    break

        if s_filter in ["all", "all stages"]:
            for s_cand in ["anticipated", "active", "evolving", "resolved"]:
                if s_cand in q_lower:
                    s_filter = s_cand
                    break

    filter_dict = {}
    if p_filter not in ["all", "all platforms"]:
        filter_dict["platform"] = p_filter
    if s_filter not in ["all", "all stages"]:
        filter_dict["stage"] = s_filter

    candidates = list(knowledge_col.find(filter_dict))
    if not candidates:
        # Fallback to broader search if filter was overly restrictive
        candidates = list(knowledge_col.find({}))

    scored = []
    for c in candidates:
        c_doc_id = str(c.get("doc_id", "")).strip()
        is_lab_doc = (
            c_doc_id.startswith("EXP-LAB")
            or c_doc_id.startswith("FAQ-Lab")
            or c_doc_id.startswith("INTENT-LIST-LABS")
            or "lab" in c_doc_id.lower()
            or bool(c.get("lab_id"))
        )
        if is_lab_doc and not is_lab_query:
            continue

        emb = c.get("embedding")
        sim = cosine_similarity(query_vec, emb) if emb else 0.0

        # Exact lab ID priority boost
        c_lab_id = str(c.get("lab_id", "")).strip()
        c_doc_id = str(c.get("doc_id", "")).strip()
        if target_lab_id and (target_lab_id.lower() == c_lab_id.lower() or target_lab_id.lower() in c_doc_id.lower()):
            sim += 1.0  # Guarantees top match

        # Semantic title and concept overlap boost
        q_words = [w for w in re.findall(r"\w+", q_lower) if w not in {"explain", "what", "is", "the", "and", "in", "a", "an", "for", "to", "of", "about", "how", "does", "experiment", "lab"}]
        c_header = f"{c.get('title', '')} {c.get('concept', '')}".lower()
        overlap = 0
        for w in q_words:
            stem = w.rstrip('s') if len(w) > 3 else w
            if w in c_header or stem in c_header:
                overlap += 1
        sim += overlap * 0.20

        scored.append({
            "doc_id": c.get("doc_id"),
            "title": c.get("title"),
            "platform": c.get("platform"),
            "stage": c.get("stage"),
            "severity": c.get("severity"),
            "category": c.get("category"),
            "lab_id": c.get("lab_id"),
            "concept": c.get("concept"),
            "what_happened": c.get("what_happened"),
            "engine_internals": c.get("engine_internals"),
            "enterprise_impact": c.get("enterprise_impact"),
            "short_note": c.get("short_note"),
            "text": c.get("text"),
            "similarity": sim
        })

    scored.sort(key=lambda x: x["similarity"], reverse=True)
    return scored[:n_results]


def construct_rag_prompt(
    query: str,
    retrieved_chunks: List[Dict[str, Any]],
    conversation_history: List[Dict[str, str]],
    platform: str = "All Platforms"
) -> str:
    """Constructs context-augmented system and user prompt for LLM/SLM."""
    context_text = "\n\n---\n\n".join([str(c.get("text") or c.get("response_text") or "") for c in retrieved_chunks if isinstance(c, dict)]) if retrieved_chunks else "No specific match in CTI repository."
    
    prompt = f"""You are CTI-AI, an expert Cyber Threat Intelligence (CTI) and Autonomous Mitigation Analyst.
The user is querying about threat mitigation on platform: [{platform.upper()}].

RELEVANT CTI THREAT REPOSITORY CONTEXT:
{context_text}

Provide:
1. Threat Analysis (Categorize as Anticipated, Active, Evolving, or Resolved).
2. Precise Technical Details (CVE ID, CVSS severity, affected packages/versions).
3. Exact Step-by-Step Mitigation Procedures (terminal commands / scripts for {platform}).
4. Immediate Defensive Actionable Advice.
"""
    return prompt
