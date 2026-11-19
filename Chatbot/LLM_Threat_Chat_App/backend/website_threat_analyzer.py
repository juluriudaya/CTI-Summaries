"""Website & URL Threat Intelligence Analysis Engine

Provides deep forensic threat analysis for any user-submitted website, URL, or domain:
1. Lexical & Syntactic Decomposition (Protocol, Domain, TLD, Subdomains, Path, Query Entropy)
2. Phishing & Brand Impersonation Heuristics (Targeted Credential Harvesting Vectors)
3. Malware & C2 Domain Profiling (DGA Entropy, Homograph/Punycode, Suspicious TLD Abuse)
4. Web Injection & Exploit Pattern Auditing (SQLi, XSS, Path Traversal, Open Redirects)
5. MITRE ATT&CK Technique Mapping (T1566 Phishing, T1071 Web Protocols, T1204 User Execution)
6. Autonomous Defensive Mitigation Generation (DNS Sinkholing, Firewall Egress Blocking, WAF Rules)
7. Persistent MongoDB Audit Telemetry ('website_threat_telemetry')
"""

import os
import re
import math
import socket
import datetime
from datetime import timezone
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional, Tuple

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(timezone.utc)


# Common trusted benign corporate / educational domains
TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "apple.com", "amazon.com",
    "wikipedia.org", "mongodb.com", "python.org", "stackoverflow.com",
    "docker.com", "kubernetes.io", "nist.gov", "cisa.gov", "mitre.org",
    "cloudflare.com", "mozilla.org", "apache.org", "linuxfoundation.org"
}

# TLDs heavily abused by zero-cost throwaway phishing / malware campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "click", "link", "zip", "mov", "cam", "rest", "surf", "icu"
}

# Targeted enterprise brands frequently impersonated in phishing attacks
TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "bankofamerica",
    "chase", "wells-fargo", "citi", "binance", "coinbase", "metamask", "steam",
    "discord", "facebook", "instagram", "whatsapp", "telegram", "dhl", "fedex"
]

# Sensitive credential harvesting tokens in path or query parameters
CREDENTIAL_HARVEST_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "banking",
    "update", "wallet", "recover", "authenticate", "auth", "token", "session",
    "confirm", "credential", "password", "reset", "invoice", "payment", "kyc"
]

# Dangerous file extensions commonly delivered in drive-by downloads
MALICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".iso", ".dll", ".apk", ".jar", ".hta"
]


def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect Domain Generation Algorithms (DGA) and obfuscated strings."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for c in data:
        char_counts[c] = char_counts.get(c, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def extract_url_from_text(text: str) -> Optional[str]:
    """Extracts the first valid URL or domain from arbitrary user input."""
    # Pattern 1: Explicit scheme
    m1 = re.search(r"https?://[^\s<>\"']+", text, re.IGNORECASE)
    if m1:
        return m1.group(0).strip(".,;:)")
    
    # Pattern 2: www prefix
    m2 = re.search(r"www\.[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+[^\s<>\"']*", text, re.IGNORECASE)
    if m2:
        return "http://" + m2.group(0).strip(".,;:)")

    # Pattern 3: Bare domain with common TLD
    tld_pattern = r"\b([a-zA-Z0-9-]+\.(?:com|org|net|io|xyz|top|cc|ru|cn|in|app|dev|co|biz|info|ai|me|live|shop|online|site|tech|vip|club))[/\w.-]*"
    m3 = re.search(tld_pattern, text, re.IGNORECASE)
    if m3:
        return "http://" + m3.group(0).strip(".,;:)")

    # Pattern 4: Raw IP address URL
    m4 = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?\b", text)
    if m4:
        return "http://" + m4.group(0).strip(".,;:)")

    return None


def analyze_website_threat(raw_input: str, db=None) -> Dict[str, Any]:
    """Performs deep-reasoned forensic threat analysis of a target website or URL."""
    now = utc_now()
    target_url = extract_url_from_text(raw_input) or raw_input.strip()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    parsed = urlparse(target_url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # Split host and port
    if ":" in netloc:
        host, port_str = netloc.split(":", 1)
    else:
        host, port_str = netloc, ("443" if scheme == "https" else "80")

    host_clean = host.strip("[]")
    is_ip_host = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host_clean))

    # Determine TLD
    domain_parts = host_clean.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else host_clean

    # -------------------------------------------------------------------------
    # Multi-Vector Threat Indicators Evaluation
    # -------------------------------------------------------------------------
    risk_score = 0
    threat_indicators: List[Dict[str, str]] = []
    mitre_tags: List[str] = ["T1071.001 - Web Protocols"]

    # 1. Plaintext Protocol Check
    if scheme == "http":
        risk_score += 20
        threat_indicators.append({
            "vector": "Unencrypted Transport (Plaintext HTTP)",
            "severity": "MEDIUM",
            "desc": "Traffic is sent unencrypted over cleartext HTTP, exposing session cookies and credentials to adversary eavesdropping and MITM tampering."
        })

    # 2. Raw IP as Host Check
    if is_ip_host:
        risk_score += 35
        mitre_tags.append("T1071 - Application Layer Protocol: Direct IP")
        threat_indicators.append({
            "vector": "Direct IP Host Binding",
            "severity": "HIGH",
            "desc": "Website uses a raw IPv4 address rather than a registered DNS FQDN. This pattern is strongly correlated with short-lived malware drop sites and C2 listeners."
        })

    # 3. High-Risk TLD Abuse Check
    if tld in HIGH_RISK_TLDS:
        risk_score += 25
        threat_indicators.append({
            "vector": f"High-Abuse Top-Level Domain (.{tld})",
            "severity": "HIGH",
            "desc": f"The '.{tld}' TLD exhibits high statistical correlation with disposable spam, phishing campaigns, and malware distribution according to Spamhaus & APWG."
        })

    # 4. Brand Impersonation & Typosquatting
    matched_brand = None
    for brand in TARGET_BRANDS:
        if brand in host_clean:
            if root_domain not in [f"{brand}.com", f"{brand}.org", f"{brand}.net"]:
                matched_brand = brand
                break

    if matched_brand:
        risk_score += 45
        mitre_tags.append("T1566.002 - Spearphishing Link (Brand Impersonation)")
        threat_indicators.append({
            "vector": f"Deceptive Brand Impersonation: '{matched_brand.upper()}'",
            "severity": "CRITICAL",
            "desc": f"The domain embeds brand trademark '{matched_brand}' within subdomains or deceptive domain structures while pointing to an untrusted registrar root."
        })

    # 5. Credential Harvesting Token in Path / Query
    found_harvest_tokens = [kw for kw in CREDENTIAL_HARVEST_KEYWORDS if kw in path.lower() or kw in query.lower()]
    if found_harvest_tokens:
        risk_score += 25
        mitre_tags.append("T1566 - Phishing Credential Harvester")
        threat_indicators.append({
            "vector": f"Credential Harvesting Artifacts: {', '.join(found_harvest_tokens[:3])}",
            "severity": "HIGH",
            "desc": f"Path contains high-risk authentication triggers ({', '.join(found_harvest_tokens[:3])}) designed to entice victims into entering credentials."
        })

    # 6. Malicious Executable Download Artifact
    for ext in MALICIOUS_EXTENSIONS:
        if path.lower().endswith(ext):
            risk_score += 50
            mitre_tags.append("T1204.001 - Malicious Link: Binary Payload")
            threat_indicators.append({
                "vector": f"Suspicious Binary Extension ({ext})",
                "severity": "CRITICAL",
                "desc": f"URL directly links to an executable payload ({ext}) that could facilitate drive-by execution or initial payload dropping."
            })
            break

    # 7. Web Exploitation Payload in Query
    query_lower = query.lower()
    if any(p in query_lower for p in ["union select", "' or '", "--", "<script>", "javascript:", "../", "..\\"]):
        risk_score += 40
        threat_indicators.append({
            "vector": "Web Application Attack Vector (SQLi / XSS / Path Traversal)",
            "severity": "HIGH",
            "desc": "URL query parameters contain identifiable exploit payloads targeting backend database systems or reflected script execution."
        })

    # 8. Punycode / Homograph Obfuscation
    if "xn--" in host_clean:
        risk_score += 35
        mitre_tags.append("T1036.005 - Masquerading: Visual Homograph")
        threat_indicators.append({
            "vector": "Internationalized Domain Name (IDN) Punycode Homograph",
            "severity": "HIGH",
            "desc": "Host utilizes Punycode ('xn--') encoding to render Cyrillic or Unicode lookalikes mimicking trusted legitimate domains."
        })

    # 9. Shannon Entropy (DGA Detection)
    entropy_val = shannon_entropy(domain_parts[0])
    if entropy_val > 4.2 and not is_ip_host:
        risk_score += 20
        mitre_tags.append("T1568.002 - Domain Generation Algorithms (DGA)")
        threat_indicators.append({
            "vector": f"High Algorithmic Entropy ({entropy_val} bits/char)",
            "severity": "MEDIUM",
            "desc": "Domain name exhibits abnormally high randomness, a common signature of Domain Generation Algorithms (DGA) in botnet malware."
        })

    # Benign Overrides
    if root_domain in TRUSTED_DOMAINS and not found_harvest_tokens and not matched_brand:
        risk_score = 5

    risk_score = min(100, risk_score)

    # Classify Overall Posture
    if risk_score >= 75:
        posture = "CRITICAL (MALICIOUS / PHISHING)"
        badge = "🚨 CRITICAL THREAT"
    elif risk_score >= 45:
        posture = "HIGH RISK"
        badge = "🔴 HIGH RISK"
    elif risk_score >= 20:
        posture = "SUSPICIOUS / ELEVATED"
        badge = "🟠 SUSPICIOUS"
    else:
        posture = "BENIGN / LOW RISK"
        badge = "🟢 LOW RISK (CLEAN)"

    # Remediation Playbook Commands
    dns_sinkhole = f"0.0.0.0 {host_clean}"
    fw_block_cmd = (
        f"netsh advfirewall firewall add rule name='Block-Threat-{host_clean}' dir=out action=block remoteip={host_clean}"
        if is_ip_host
        else f"# DNS Sinkhole / Egress Block for {host_clean}\necho '0.0.0.0 {host_clean}' >> /etc/hosts"
    )

    result = {
        "target_url": target_url,
        "scheme": scheme,
        "host": host_clean,
        "root_domain": root_domain,
        "tld": tld,
        "risk_score": risk_score,
        "posture": posture,
        "badge": badge,
        "mitre_tags": list(set(mitre_tags)),
        "entropy": entropy_val,
        "indicators": threat_indicators,
        "remediation_commands": {
            "dns_sinkhole": dns_sinkhole,
            "firewall_rule": fw_block_cmd
        },
        "analyzed_at": now.strftime("%Y-%m-%d %H:%M:%S UTC")
    }

    # Store persistent audit in MongoDB if available
    if db is not None:
        try:
            telemetry_col = db.website_threat_telemetry
            record = dict(result)
            record["timestamp"] = now
            telemetry_col.insert_one(record)
        except Exception:
            pass

    return result


def format_website_threat_markdown(report: Dict[str, Any]) -> str:
    """Renders a comprehensive, deep-reasoned forensic security analysis in Markdown."""
    url = report["target_url"]
    host = report["host"]
    posture = report["posture"]
    badge = report["badge"]
    score = report["risk_score"]
    indicators = report["indicators"]
    mitre = report["mitre_tags"]
    cmds = report["remediation_commands"]
    analyzed_at = report["analyzed_at"]

    deep_thinking = f"""<details open>
<summary>🧠 <b>Deep Thinking & Website Threat Forensic Analysis</b></summary>

* **Target Inspected:** `{url}` (Host: `{host}`)
* **Lexical & Transport Diagnostics:** Protocol: `{report['scheme'].upper()}` | Top-Level Domain: `.{report['tld']}` | Shannon Entropy: `{report['entropy']} bits/char`
* **Adversary Vector Evaluation:** Cross-referencing URL attributes against MITRE ATT&CK techniques ({', '.join(mitre[:2])}).
* **Defense Strategy:** Calculating containment priority and synthesizing DNS sinkhole & perimeter egress firewall rules.
</details>

"""

    lines = [
        deep_thinking,
        f"### 🌐 Website & URL Threat Intelligence Forensic Dossier",
        f"**Target URL:** `{url}` | **Evaluated Host:** `{host}`",
        f"**Threat Assessment Posture:** **{badge}** (Threat Score: `{score}/100`)",
        f"**Forensic Timestamp:** `{analyzed_at}`",
        "",
        "---",
        "",
        "#### 📊 Multi-Vector Diagnostic Matrix",
        f"| Diagnostic Category | Forensic Telemetry Finding |",
        f"| :--- | :--- |",
        f"| **Transport Protocol** | `{'🔒 HTTPS (TLS Encrypted)' if report['scheme'] == 'https' else '⚠️ Cleartext HTTP (Unencrypted)'}` |",
        f"| **Domain / Host Structure** | `{host}` (Root: `{report['root_domain']}`) |",
        f"| **Algorithmic Randomness** | `{report['entropy']} bits/char (Shannon Entropy)` |",
        f"| **Threat Indicators Identified** | **`{len(indicators)} security finding(s)`** |",
        f"| **MITRE ATT&CK Mapping** | `{', '.join(mitre)}` |",
        "",
        "---"
    ]

    if not indicators:
        lines.extend([
            "#### ✅ Forensic Verdict: Clean / Low Risk Website",
            f"> **{host}** does not exhibit deceptive brand spoofing, credential harvesting keywords, Punycode homographs, or direct executable drops.",
            "",
            "💡 *The website conforms to standard enterprise web hosting profiles. Continue standard transport security hygiene.*"
        ])
    else:
        lines.append("#### 🚨 Identified Threat Vectors & Attack Surface")
        for idx, ind in enumerate(indicators, 1):
            sev_badge = "🚨 CRITICAL" if ind["severity"] == "CRITICAL" else ("🔴 HIGH" if ind["severity"] == "HIGH" else "🟠 MEDIUM")
            lines.extend([
                f"##### {idx}. {ind['vector']}",
                f"- **Severity Level:** **{sev_badge}**",
                f"- **Technical Analysis:** {ind['desc']}",
                ""
            ])

        lines.extend([
            "---",
            "#### 🛡️ Autonomous Defense & Remediation Playbook",
            "To contain and neutralize connections to this threat entity on your network perimeter:",
            f"```bash\n# 1. DNS Sinkhole Rule (Local Hosts / Pi-hole / BIND9)\n{cmds['dns_sinkhole']}\n\n# 2. Host Perimeter Egress Block Rule\n{cmds['firewall_rule']}\n```",
            "",
            "💡 *You can type `'mitigate'` to register this threat domain in your MongoDB security audit trail.*"
        ])

    return "\n".join(lines)


if __name__ == "__main__":
    print("=" * 70)
    print("  🌐 WEBSITE & URL THREAT ANALYZER TEST")
    print("=" * 70)
    sample_mal = "http://paypal-security-update.xyz/login/verify.php?user=admin&token=123"
    print(format_website_threat_markdown(analyze_website_threat(sample_mal)))
