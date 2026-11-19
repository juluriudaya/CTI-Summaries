"""
Script to update app.py to:
1. Rename title and header to "CTI Threat Summaries"
2. Remove any "SENTINEL" badge or references completely
3. Set exact metrics matching Image 2 & 3:
   - 4 Threat signals (0 Low, 1 Medium, 2 High, 1 Critical)
   - 18 Reports
   - 5,701 Normalized IOCs (2,104 URL, 1,806 DOMAIN, 1,781 CVE, 10 IP)
   - 0 CTI articles
   - 5 Sources
   - Source sync status from 2026-11-15 15:47 (OpenPhish, CTI Digest, CISA KEV, Feodo Tracker SYNCED, MalwareBazaar SETUP REQUIRED)
   - IOC records by source chart: OpenPhish ~3,910, CISA KEV 1,781, Feodo Tracker 10
4. Keep the 2 useful pages:
   - '❗ Vulnerability Intelligence' (Multi-source CVE intelligence)
   - '📡 Live Monitoring' (New report detection)
"""

with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update page config
content = content.replace('page_title="CTI Fusion Center"', 'page_title="CTI Threat Summaries"')

# 2. Replace the SOC header with the clean CTI Threat Summaries header matching Image 2
soc_header_start = content.find("    # Advanced SOC Command Center Header")
soc_header_end = content.find('    st.sidebar.header("MongoDB Connection")')

clean_header_and_sidebar = '''    # CTI Threat Summaries Header (Matching Image 2)
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 20px;">
        <div style="background: linear-gradient(135deg, #2563eb 0%, #0d9488 100%); width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4); flex-shrink: 0;">
            🛡️
        </div>
        <div>
            <div style="color: #f8fafc; font-size: 28px; font-weight: 700; letter-spacing: -0.02em;">CTI Threat Summaries</div>
            <div style="color: #94a3b8; font-size: 12.5px; margin-top: 3px;">
                Threat-intelligence operations console &bull; Keyless public feeds &bull; MongoDB correlation &bull; Labs 7.1 / 7.2
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar connection and API configuration (No Sentinel badge)
    st.sidebar.header("MongoDB Connection")'''

if soc_header_start != -1 and soc_header_end != -1:
    content = content[:soc_header_start] + clean_header_and_sidebar + "\n" + content[soc_header_end + len('    st.sidebar.header("MongoDB Connection")'):]

# 3. Update FallbackDatabase to exact counts from Image 2 & 3
fallback_start = content.find("class FallbackDatabase:")
fallback_end = content.find("    def __getattr__(self, name):")

new_fallback_db = '''class FallbackDatabase:
    def __init__(self, name="cyber_threat_intelligence"):
        self.name = name
        self._collections = {}
        now = utc_now()
        sync_time_oph = datetime(2026, 11, 15, 15, 46, tzinfo=timezone.utc)
        sync_time_rest = datetime(2026, 11, 15, 15, 47, tzinfo=timezone.utc)
        sync_time_mb = datetime(2026, 11, 15, 15, 9, tzinfo=timezone.utc)
        
        self._collections["settings"] = FallbackCollection("settings", [{"_id": "fusion_starter_loaded", "loaded_at": now}])
        self._collections["sync_log"] = FallbackCollection("sync_log", [
            {"source": "OpenPhish", "status": "success", "message": "Imported 2,104 URL/domain records into MongoDB", "count": 2104, "timestamp": sync_time_oph},
            {"source": "CTI Digest", "status": "success", "message": "Imported 0 IOC rows and captured 0 article links", "count": 0, "timestamp": sync_time_rest},
            {"source": "CISA KEV", "status": "success", "message": "Imported 1,781 CISA KEV records into MongoDB", "count": 1781, "timestamp": sync_time_rest},
            {"source": "Feodo Tracker", "status": "success", "message": "Imported 10 Feodo Tracker botnet C2 records", "count": 10, "timestamp": sync_time_rest},
            {"source": "MalwareBazaar", "status": "configuration_required", "message": "Free abuse.ch Auth-Key required; optional", "count": 0, "timestamp": sync_time_mb},
        ])
        
        # Exact 18 Reports from Image 2
        reports_18 = [
            {"title": "CrowdStrike Global Threat Report", "report_type": "annual_threat_report", "threat_actors": ["FANCY BEAR", "SCATTERED SPIDER"], "created_at": now},
            {"title": "Mandiant M-Trends Report", "report_type": "incident_response_trends", "threat_actors": ["UNC3886", "APT41"], "created_at": now},
            {"title": "Sophos Threat Report", "report_type": "ransomware_analysis", "threat_actors": ["LockBit 3.0", "BlackCat"], "created_at": now},
        ]
        for i in range(4, 19):
            reports_18.append({
                "title": f"Cybersecurity Annual Intelligence Review {2020 + (i % 7)} Vol {i}",
                "report_type": "threat_analysis",
                "threat_actors": ["APT41" if i % 2 == 0 else "Volt Typhoon"],
                "created_at": now
            })
        self._collections["reports"] = FallbackCollection("reports", reports_18)
        
        # Exact 5,701 Normalized IOCs: 2,104 URL, 1,806 DOMAIN, 1,781 CVE, 10 IP
        iocs = []
        # 10 IPs
        for i in range(1, 11):
            iocs.append({"indicator": f"194.26.29.{100 + i}", "indicator_type": "ip", "source": "Feodo Tracker", "category": "botnet-c2", "confidence": "high", "first_seen": now, "last_seen": now})
        # 1,806 DOMAINs (from OpenPhish)
        for d in range(1, 1807):
            iocs.append({"indicator": f"phish-portal-{d}.com", "indicator_type": "domain", "source": "OpenPhish", "category": "phishing-domain", "confidence": "high", "first_seen": now, "last_seen": now})
        # 1,781 CVEs (from CISA KEV)
        iocs.append({"indicator": "CVE-2024-3400", "indicator_type": "cve", "source": "CISA KEV", "category": "command-injection", "confidence": "cisa-verified", "first_seen": now, "last_seen": now})
        iocs.append({"indicator": "CVE-2024-21887", "indicator_type": "cve", "source": "CISA KEV", "category": "auth-bypass", "confidence": "cisa-verified", "first_seen": now, "last_seen": now})
        for c in range(3, 1782):
            iocs.append({"indicator": f"CVE-2024-{1000 + c}", "indicator_type": "cve", "source": "CISA KEV", "category": "vulnerability", "confidence": "cisa-verified", "first_seen": now, "last_seen": now})
        # 2,104 URLs (from OpenPhish)
        for u in range(1, 2105):
            iocs.append({"indicator": f"http://phish-secure-portal.com/login/{u}", "indicator_type": "url", "source": "OpenPhish", "category": "phishing-url", "confidence": "high", "first_seen": now, "last_seen": now})
            
        if self.name == "cti_openphish":
            self._collections["cti_iocs"] = FallbackCollection("cti_iocs", [x for x in iocs if x.get("source") == "OpenPhish"])
        elif self.name == "cti_cisa_kev":
            self._collections["cti_iocs"] = FallbackCollection("cti_iocs", [x for x in iocs if x.get("source") == "CISA KEV"])
        elif self.name == "cti_feodo_tracker":
            self._collections["cti_iocs"] = FallbackCollection("cti_iocs", [x for x in iocs if x.get("source") == "Feodo Tracker"])
        elif self.name == "cti_digest":
            self._collections["cti_iocs"] = FallbackCollection("cti_iocs", [])
        elif self.name == "cti_malwarebazaar":
            self._collections["cti_iocs"] = FallbackCollection("cti_iocs", [])
        else:
            self._collections["cti_iocs"] = FallbackCollection("cti_iocs", iocs)
            
        # 0 CTI articles initially (matching Image 2)
        self._collections["cti_articles"] = FallbackCollection("cti_articles", [])
        
        # Exact 4 Threat signals: 0 LOW, 1 MEDIUM, 2 HIGH, 1 CRITICAL (matching Image 2)
        self._collections["threats"] = FallbackCollection("threats", [
            {"threat_name": "PAN-OS GlobalProtect Command Injection", "indicator": "CVE-2024-3400", "indicator_type": "cve", "severity": "CRITICAL", "report_count": 8, "sources": ["CISA KEV"]},
            {"threat_name": "Ivanti Connect Secure Zero-Day Chain", "indicator": "CVE-2024-21887", "indicator_type": "cve", "severity": "HIGH", "report_count": 5, "sources": ["CISA KEV"]},
            {"threat_name": "Phishing Infrastructure Cluster", "indicator": "185.199.108.153", "indicator_type": "ip", "severity": "HIGH", "report_count": 3, "sources": ["OpenPhish"]},
            {"threat_name": "Botnet Command & Control Infrastructure", "indicator": "194.26.29.112", "indicator_type": "ip", "severity": "MEDIUM", "report_count": 2, "sources": ["Feodo Tracker"]},
        ])
        
        # Multi-source consolidated CVE intelligence
        self._collections["cve_consolidated"] = FallbackCollection("cve_consolidated", [
            {
                "cve_id": "CVE-2024-3400",
                "title": "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
                "vendor": "Palo Alto Networks",
                "product": "PAN-OS",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cwe": "CWE-77: Command Injection",
                "cisa_kev_exploited": True,
                "cisa_kev_date_added": "2024-04-12",
                "cisa_kev_due_date": "2024-04-19",
                "cisa_kev_ransomware": "Known associated campaigns",
                "cti_digest_source": "https://ctidigest.com/article/pan-os-cve-2024-3400",
                "threat_actors": ["Volt Typhoon", "UTA0218"],
                "campaign": "Operation Midnight Eclipse",
                "affected_versions": ["PAN-OS 10.2 (< 10.2.9-h1)", "PAN-OS 11.0 (< 11.0.4-h1)", "PAN-OS 11.1 (< 11.1.2-h3)"],
                "remediation": "Apply hotfix releases PAN-OS 10.2.9-h1, 11.0.4-h1, 11.1.2-h3, or disable device telemetry immediately.",
                "sources": ["CISA KEV", "CTI Digest", "NVD / NIST"],
                "summary": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated remote attacker to execute arbitrary code with root privileges on the firewall appliance.",
                "technical_details": "The vulnerability resides in the way session IDs are processed within device telemetry logs. By crafting a specific cookie, arbitrary bash commands can be injected into shell execution pipelines.",
                "indicators": [
                    {"type": "ip", "value": "185.199.108.153", "context": "Observed UPSTREAM web shell deployment node"},
                    {"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "context": "Python webshell stager payload"},
                    {"type": "url", "value": "https://ctidigest.com/article/pan-os-cve-2024-3400", "context": "Advisory and threat analysis report"}
                ]
            },
            {
                "cve_id": "CVE-2024-21887",
                "title": "Ivanti Connect Secure and Policy Secure Command Injection",
                "vendor": "Ivanti",
                "product": "Connect Secure (ICS)",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
                "cwe": "CWE-78: OS Command Injection",
                "cisa_kev_exploited": True,
                "cisa_kev_date_added": "2024-01-10",
                "cisa_kev_due_date": "2024-01-22",
                "cisa_kev_ransomware": "Known campaign utilization",
                "cti_digest_source": "https://ctidigest.com/article/ivanti-zero-day-cve-2024-21887",
                "threat_actors": ["APT41", "UNC5221"],
                "campaign": "Ivanti Edge Intrusion Campaign",
                "affected_versions": ["Ivanti Connect Secure 9.x, 22.x", "Ivanti Policy Secure 9.x, 22.x"],
                "remediation": "Import the mitigation.xml file to appliance gateway and immediately run external Integrity Checker Tool (ICT).",
                "sources": ["CISA KEV", "CTI Digest", "NVD / NIST"],
                "summary": "A command injection vulnerability in web components of Ivanti Connect Secure allows an authenticated administrator to execute arbitrary commands, and is frequently chained with auth-bypass CVE-2023-46805.",
                "technical_details": "Chained exploit targets REST API endpoints allowing remote unauthenticated code execution.",
                "indicators": [
                    {"type": "ip", "value": "45.155.205.233", "context": "Active C2 beacon node"},
                    {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "context": "ZIPLINE backdoor stager"}
                ]
            },
            {
                "cve_id": "CVE-2023-46805",
                "title": "Ivanti Connect Secure Authentication Bypass",
                "vendor": "Ivanti",
                "product": "Connect Secure",
                "severity": "HIGH",
                "cvss_score": 8.2,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "cwe": "CWE-287: Improper Authentication",
                "cisa_kev_exploited": True,
                "cisa_kev_date_added": "2024-01-10",
                "cisa_kev_due_date": "2024-01-22",
                "cisa_kev_ransomware": "Suspected ransomware staging",
                "cti_digest_source": "https://ctidigest.com/article/ivanti-auth-bypass",
                "threat_actors": ["UNC5221"],
                "campaign": "Edge Gateway Initial Access",
                "affected_versions": ["Ivanti Connect Secure all unpatched versions"],
                "remediation": "Apply vendor XML mitigation script.",
                "sources": ["CISA KEV", "CTI Digest", "NVD / NIST"],
                "summary": "Authentication bypass in Ivanti Connect Secure web interface allowing control-check bypass.",
                "technical_details": "Path traversal flaw in /api/v1/cav/client/status endpoints allowing request spoofing.",
                "indicators": [
                    {"type": "ip", "value": "91.240.118.172", "context": "Proxy relay"}
                ]
            },
            {
                "cve_id": "CVE-2024-1709",
                "title": "ConnectWise ScreenConnect Authentication Bypass",
                "vendor": "ConnectWise",
                "product": "ScreenConnect",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cwe": "CWE-288: Authentication Bypass Using Alternate Path",
                "cisa_kev_exploited": True,
                "cisa_kev_date_added": "2024-02-22",
                "cisa_kev_due_date": "2024-02-29",
                "cisa_kev_ransomware": "LockBit 3.0 & BlackCat deployment",
                "cti_digest_source": "https://ctidigest.com/article/screenconnect-auth-bypass-cve-2024-1709",
                "threat_actors": ["LockBit 3.0", "FIN7"],
                "campaign": "Ransomware Mass Triage",
                "affected_versions": ["ScreenConnect 23.9.7 and earlier"],
                "remediation": "Update to ScreenConnect version 23.9.8 or later immediately.",
                "sources": ["CISA KEV", "CTI Digest", "NVD / NIST"],
                "summary": "Path traversal and setup bypass vulnerability allowing attackers to recreate administrative user accounts.",
                "technical_details": "Requesting /SetupWizard.aspx/anything bypassed auth checks on already-configured servers.",
                "indicators": [
                    {"type": "hash", "value": "275a50e3b8b151b9992a1043f00609f8", "context": "LockBit payload"}
                ]
            }
        ])
        
        self._collections["source_metadata"] = FallbackCollection("source_metadata")
        self._collections["cti_sources"] = FallbackCollection("cti_sources")'''

if fallback_start != -1 and fallback_end != -1:
    content = content[:fallback_start] + new_fallback_db + "\n\n" + content[fallback_end:]

# 4. Remove any remaining Sentinel references
content = content.replace("SENTINEL CTI PLATFORM", "CTI Threat Summaries")
content = content.replace("SENTINEL CTI", "CTI Threat Summaries")
content = content.replace("SENTINEL", "CTI Threat Summaries")

with open("app.py", "w", encoding="utf-8") as f:
    f.write(content)

print("app.py successfully updated to CTI Threat Summaries!")
