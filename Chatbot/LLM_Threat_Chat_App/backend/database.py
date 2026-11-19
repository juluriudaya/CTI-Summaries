"""Database & Data Model Layer for CTI LLM Chat Application

Implements:
1. MongoDB client connection with environment variables (Exercise-12)
2. Collections:
   - 'knowledge': Chunks for RAG Vector Search (Section A.2)
   - 'sessions': Conversation memory store (Section A.4)
   - 'threat_lifecycle': Anticipated, Active, Evolving, Resolved threats across platforms
   - 'vulnerabilities_detected': Scanner bot findings pending confirmation
   - 'remediation_audit': Verified audit logs of conversational mitigation actions
3. Resilient In-Memory Fallback if MongoDB daemon is offline.
"""

import os
import uuid
import datetime
from datetime import timezone
from typing import List, Dict, Any, Optional
import pymongo
from pymongo import MongoClient

DEFAULT_MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DEFAULT_DB_NAME = os.getenv("MONGO_DB", "llm_threat_intel")


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(timezone.utc)


def is_mongo_alive(uri: str, timeout_ms: int = 400) -> bool:
    try:
        import socket
        from urllib.parse import urlparse
        p = urlparse(uri)
        host = p.hostname or "127.0.0.1"
        port = p.port or 27017
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex((host, port)) != 0:
                return False
        client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
        client.admin.command("ping")
        return True
    except Exception:
        return False


# -----------------------------------------------------------------------------
# In-Memory Fallback Collection & Database
# -----------------------------------------------------------------------------

class MemoryCollection:
    def __init__(self, name: str, docs: Optional[List[Dict[str, Any]]] = None):
        self.name = name
        self.docs = list(docs or [])

    def __bool__(self):
        return True

    def count_documents(self, filter_dict=None) -> int:
        if not filter_dict:
            return len(self.docs)
        return len([d for d in self.docs if self._matches(d, filter_dict)])

    def estimated_document_count(self) -> int:
        return len(self.docs)

    def find(self, filter_dict=None, sort=None, limit=0) -> List[Dict[str, Any]]:
        res = [d for d in self.docs if self._matches(d, filter_dict or {})]
        if sort:
            for field, order in reversed(sort):
                res.sort(key=lambda x: x.get(field, ""), reverse=(order < 0))
        if limit > 0:
            res = res[:limit]
        return res

    def find_one(self, filter_dict=None) -> Optional[Dict[str, Any]]:
        for d in self.docs:
            if self._matches(d, filter_dict or {}):
                return d
        return None

    def insert_one(self, doc: Dict[str, Any]):
        d = dict(doc)
        if "_id" not in d:
            d["_id"] = str(uuid.uuid4())
        self.docs.append(d)
        class Res:
            inserted_id = d["_id"]
        return Res()

    def update_one(self, filter_dict: Dict[str, Any], update_dict: Dict[str, Any], upsert: bool = False):
        d = self.find_one(filter_dict)
        if d:
            if "$set" in update_dict:
                d.update(update_dict["$set"])
        elif upsert:
            new_doc = dict(filter_dict)
            if "$set" in update_dict:
                new_doc.update(update_dict["$set"])
            self.insert_one(new_doc)

    def aggregate(self, pipeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Mock vectorSearch or group aggregation
        for stage in pipeline:
            if "$vectorSearch" in stage:
                return self.docs[: stage["$vectorSearch"].get("limit", 3)]
        return self.docs

    def _matches(self, doc: Dict[str, Any], filter_dict: Dict[str, Any]) -> bool:
        for k, v in filter_dict.items():
            if k == "$or":
                return any(self._matches(doc, sub) for sub in v)
            if doc.get(k) != v:
                return False
        return True


class MemoryDatabase:
    def __init__(self, name: str = DEFAULT_DB_NAME):
        self.name = name
        self._collections: Dict[str, MemoryCollection] = {}

    def __bool__(self):
        return True

    def __getattr__(self, name: str) -> MemoryCollection:
        if name not in self._collections:
            self._collections[name] = MemoryCollection(name)
        return self._collections[name]

    def __getitem__(self, name: str) -> MemoryCollection:
        return getattr(self, name)


# -----------------------------------------------------------------------------
# Database Factory & Seeding
# -----------------------------------------------------------------------------

_MEM_DB = None

def get_database(uri: str = DEFAULT_MONGO_URI, db_name: str = DEFAULT_DB_NAME):
    global _MEM_DB
    if is_mongo_alive(uri):
        client = MongoClient(uri)
        db = client[db_name]
        seed_threat_data(db)
        return db
    else:
        if _MEM_DB is None:
            _MEM_DB = MemoryDatabase(db_name)
            seed_threat_data(_MEM_DB)
        return _MEM_DB


# -----------------------------------------------------------------------------
# Comprehensive Threat Knowledge & Lifecycle Catalog
# -----------------------------------------------------------------------------

INITIAL_THREATS = [
    # WINDOWS PLATFORM
    {
        "threat_id": "THREAT-WIN-001",
        "name": "BlackCat / ALPHV Ransomware Active Campaign",
        "platform": "windows",
        "stage": "active",
        "cve": "CVE-2024-21887",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "affected_versions": "Windows Server 2016/2019/2022, Windows 10/11",
        "description": "Active in-the-wild extortion campaign deploying Rust-based polymorphic payloads using compromised Ivanti and Active Directory credentials. Initiates shadow copy deletion and BitLocker tampering.",
        "indicators": ["185.220.101.5", "alphv_encryptor.exe", "vssadmin delete shadows /all /quiet"],
        "mitigation_procedure": "1. Isolate compromised domain controller.\n2. Block egress traffic to IP 185.220.101.5.\n3. Enforce PowerShell Constrained Language Mode and GPO script block logging.\n4. Rotate all Kerberos Krbtgt account passwords.",
        "mitigation_commands": [
            "Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Restricted -Force",
            "netsh advfirewall firewall add rule name='Block-BlackCat-C2' dir=out action=block remoteip=185.220.101.5",
            "Auditpol /set /subcategory:'Audit Process Creation' /success:enable /failure:enable"
        ]
    },
    {
        "threat_id": "THREAT-WIN-002",
        "name": "Active Directory Certificate Services (AD CS) ESC14 Abuse",
        "platform": "windows",
        "stage": "anticipated",
        "cve": "CVE-2025-2408",
        "cvss": 8.8,
        "severity": "HIGH",
        "affected_versions": "Windows Active Directory Certificate Services 2019/2022",
        "description": "Anticipated privilege escalation vector exploiting misconfigured certificate templates allowing unprivileged domain users to impersonate domain admins via SAN (Subject Alternative Name) extension request.",
        "indicators": ["Certutil -pulse", "PKINIT authentication anomalies", "Template enrollment: SubCA-Admin"],
        "mitigation_procedure": "1. Audit certificate templates with Certify or PSPKI.\n2. Remove ENROLLEE_SUPPLIES_SUBJECT flag from sensitive templates.\n3. Restrict enrollment agent permissions to Tier-0 administrative roles.",
        "mitigation_commands": [
            "Get-CATemplate | Where-Object { $_.SubjectNameFlags -match 'EnrolleeSuppliesSubject' }",
            "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
            "Restart-Service CertSvc"
        ]
    },
    {
        "threat_id": "THREAT-WIN-003",
        "name": "LOLBin Certutil & Rundll32 Evasion Pipeline",
        "platform": "windows",
        "stage": "evolving",
        "cve": "CVE-2024-30051",
        "cvss": 7.8,
        "severity": "HIGH",
        "affected_versions": "Windows 11 22H2/23H2, Windows Server 2022",
        "description": "Evolving living-off-the-land malware adapting fileless multi-stage steganography. Uses certutil.exe to decode Base64 payloads directly into rundll32 memory without touching disk.",
        "indicators": ["certutil.exe -decode -f payload.txt payload.dll", "rundll32.exe payload.dll,DllRegisterServer"],
        "mitigation_procedure": "1. Implement Windows Defender Application Control (WDAC) to block unauthorized execution of certutil and mshta.\n2. Enable Attack Surface Reduction (ASR) rule: 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'.",
        "mitigation_commands": [
            "Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576C0A-62EC-4D74-A3E2-5755E2D1C908 -AttackSurfaceReductionRules_Actions Enabled",
            "Set-ProcessMitigation -System -Enable DEP,SEHOP"
        ]
    },
    {
        "threat_id": "THREAT-WIN-004",
        "name": "PrintNightmare Remote Code Execution",
        "platform": "windows",
        "stage": "resolved",
        "cve": "CVE-2021-34527",
        "cvss": 8.8,
        "severity": "HIGH",
        "affected_versions": "Windows Server 2012/2016/2019",
        "description": "Vulnerability in Windows Print Spooler service allowing authenticated attackers to execute remote code with SYSTEM privileges via RPC driver installation.",
        "indicators": ["Spoolsv.exe spawning cmd.exe", "RpcAddPrinterDriverEx calls from non-admin"],
        "mitigation_procedure": "1. Verified KB5005010 cumulative update applied.\n2. Disabled Print Spooler on all domain controllers and non-print server hosts.\n3. Enabled Point and Print Restrictions via Group Policy.",
        "mitigation_commands": [
            "Stop-Service -Name Spooler -Force",
            "Set-Service -Name Spooler -StartupType Disabled",
            "Get-HotFix -Id KB5005010"
        ]
    },

    # LINUX PLATFORM
    {
        "threat_id": "THREAT-LNX-001",
        "name": "Mirai-Variant SSH Brute-Force Botnet Campaign",
        "platform": "linux",
        "stage": "active",
        "cve": "CVE-2024-6387",
        "cvss": 9.0,
        "severity": "CRITICAL",
        "affected_versions": "Ubuntu 22.04/24.04, Debian 12, CentOS 7/9",
        "description": "Active global botnet aggressively scanning IPv4 space for exposed SSH port 22. Attempts default and leaked credential dictionaries, deploying ELF crypto-miners and DDoS reflection modules.",
        "indicators": ["194.26.29.112:2222", "/tmp/.x11-unix/.miner", "Failed password for root in /var/log/auth.log"],
        "mitigation_procedure": "1. Disable password authentication in sshd_config (enforce Ed25519 public keys).\n2. Change default SSH port from 22 to non-standard (e.g. 22222).\n3. Install fail2ban and configure UFW firewall rate-limiting.\n4. Terminate unauthorized background processes in /tmp.",
        "mitigation_commands": [
            "sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "systemctl restart sshd",
            "ufw limit 22/tcp",
            "apt-get install -y fail2ban && systemctl enable --now fail2ban"
        ]
    },
    {
        "threat_id": "THREAT-LNX-002",
        "name": "Netfilter nf_tables Kernel Privilege Escalation",
        "platform": "linux",
        "stage": "anticipated",
        "cve": "CVE-2024-1086",
        "cvss": 7.8,
        "severity": "HIGH",
        "affected_versions": "Linux Kernel 5.14 to 6.6",
        "description": "Anticipated local privilege escalation threat in netfilter subsystem allowing unprivileged users with user namespaces to obtain root via use-after-free in nft_verdict_init.",
        "indicators": ["Unprivileged user namespaces activation", "Kernel panic in nf_tables_newrule"],
        "mitigation_procedure": "1. Upgrade Linux kernel to 6.6.21+ or 6.8+.\n2. If immediate reboot is impossible, disable unprivileged user namespaces via sysctl.",
        "mitigation_commands": [
            "sysctl -w kernel.unprivileged_userns_clone=0",
            "echo 'kernel.unprivileged_userns_clone=0' >> /etc/sysctl.d/99-disable-userns.conf",
            "sysctl -p /etc/sysctl.d/99-disable-userns.conf"
        ]
    },
    {
        "threat_id": "THREAT-LNX-003",
        "name": "Polymorphic eBPF Syscall Hooking Rootkit",
        "platform": "linux",
        "stage": "evolving",
        "cve": "CVE-2024-36971",
        "cvss": 8.4,
        "severity": "HIGH",
        "affected_versions": "Linux Kernel 5.15+ with eBPF enabled",
        "description": "Evolving rootkit technique leveraging eBPF programs attached to tracepoints and kprobes. Hides PID directories from /proc, intercepts network sockets, and bypasses traditional auditd daemon logging.",
        "indicators": ["bpftool prog show (unnamed programs)", "bpf_probe_write_user calls in verification log"],
        "mitigation_procedure": "1. Restrict eBPF program loading to privileged root processes.\n2. Disable unprivileged bpf and enforce kernel lockdown mode.\n3. Audit active eBPF programs regularly with bpftool.",
        "mitigation_commands": [
            "sysctl -w kernel.unprivileged_bpf_disabled=1",
            "echo 'kernel.unprivileged_bpf_disabled=1' >> /etc/sysctl.d/99-ebpf.conf",
            "bpftool prog list"
        ]
    },
    {
        "threat_id": "THREAT-LNX-004",
        "name": "OpenSSH regreSSHion Signal Handler Race Condition",
        "platform": "linux",
        "stage": "resolved",
        "cve": "CVE-2024-6387",
        "cvss": 8.1,
        "severity": "HIGH",
        "affected_versions": "OpenSSH 8.5p1 to 9.7p1 on glibc-based Linux",
        "description": "Signal handler race condition in OpenSSH daemon leading to unauthenticated remote code execution as root due to SIGALRM race inside packet handling.",
        "indicators": ["LoginGraceTime timeouts without authentication", "sshd crashed with SIGSEGV"],
        "mitigation_procedure": "1. Installed patched OpenSSH package (9.8p1+).\n2. Set LoginGraceTime to 0 as temporary workaround to mitigate remote exposure.\n3. Verified vulnerability scanner confirms patched status.",
        "mitigation_commands": [
            "apt update && apt install --only-upgrade -y openssh-server",
            "ssh -V",
            "systemctl status sshd"
        ]
    },

    # MACOS PLATFORM
    {
        "threat_id": "THREAT-MAC-001",
        "name": "Atomic macOS Stealer (AMOS) Wallet & Keychain Harvesting",
        "platform": "macos",
        "stage": "active",
        "cve": "CVE-2024-44131",
        "cvss": 8.5,
        "severity": "HIGH",
        "affected_versions": "macOS Sonoma 14.x, Ventura 13.x",
        "description": "Active information stealer distributed via cracked software DMG files and fake browser updates. Prompts fake Apple system dialogs to capture user password, extracts Keychain secrets, browser cookies, and Telegram sessions.",
        "indicators": ["osascript -e 'display dialog...'", "/Users/Shared/atomic_payload", "POST to telegram-bot API endpoint"],
        "mitigation_procedure": "1. Enable Gatekeeper and restrict execution to Mac App Store and identified developers.\n2. Revoke compromised TCC (Transparency, Consent, and Control) permissions.\n3. Audit /Library/LaunchDaemons and ~/Library/LaunchAgents for unfamiliar plists.",
        "mitigation_commands": [
            "spctl --status",
            "tccutil reset All",
            "launchctl list | grep -v com.apple"
        ]
    },
    {
        "threat_id": "THREAT-MAC-002",
        "name": "macOS Safari & WebKit JIT Type Confusion Zero-Day",
        "platform": "macos",
        "stage": "anticipated",
        "cve": "CVE-2025-0144",
        "cvss": 8.8,
        "severity": "HIGH",
        "affected_versions": "macOS Sonoma 14.4+, Safari 17.x",
        "description": "Anticipated browser zero-day exploiting speculative JIT optimization in JavaScriptCore engine. Remote attackers can trigger out-of-bounds write via malicious webpage.",
        "indicators": ["com.apple.WebKit.WebContent crashing repeatedly", "High memory allocations on untrusted sites"],
        "mitigation_procedure": "1. Enable Lockdown Mode for high-risk users to disable complex web JIT compilations.\n2. Apply Apple Rapid Security Response (RSR) updates.\n3. Enforce content filtering via MDM profile.",
        "mitigation_commands": [
            "softwareupdate -l",
            "softwareupdate -ia --verbose"
        ]
    },

    # ANDROID PLATFORM
    {
        "threat_id": "THREAT-AND-001",
        "name": "SpyNote Android Banking Trojan & Keylogger",
        "platform": "android",
        "stage": "active",
        "cve": "CVE-2023-35674",
        "cvss": 8.8,
        "severity": "HIGH",
        "affected_versions": "Android 10, 11, 12, 13, 14",
        "description": "Active malware distributed via phishing SMS pretending to be banking updates. Tricks users into granting Accessibility Service access, enabling background screen recording, SMS interception, and automated OTP harvesting.",
        "indicators": ["Accessibility Service enabled for non-system APK", "Foreground service overlay 'System Update'", "Outbound traffic to 103.145.13.9:8080"],
        "mitigation_procedure": "1. Disable developer mode and prevent sideloading of unknown apps.\n2. Revoke Accessibility permissions from non-trusted apps in Settings.\n3. Scan with Google Play Protect and enforce Enterprise Mobility Management (EMM) restrictions.",
        "mitigation_commands": [
            "adb shell pm list packages -3",
            "adb shell pm revoke <package_name> android.permission.BIND_ACCESSIBILITY_SERVICE",
            "adb shell pm uninstall <package_name>"
        ]
    },
    {
        "threat_id": "THREAT-AND-002",
        "name": "Binder IPC Transaction Buffer Overflow",
        "platform": "android",
        "stage": "anticipated",
        "cve": "CVE-2025-1109",
        "cvss": 8.4,
        "severity": "HIGH",
        "affected_versions": "Android 12 to 14 (Linux Kernel 5.10/5.15)",
        "description": "Anticipated privilege escalation vector in Binder IPC driver kernel module. Sideloaded unprivileged application can craft malformed parcel transactions to gain system UID.",
        "indicators": ["Binder transaction failed with status -22", "KASAN report in dmesg"],
        "mitigation_procedure": "1. Apply monthly Android Security Patch Level (SPL).\n2. Enable SELinux Enforcing mode.\n3. Enforce strict isolatedProcess sandboxes for third-party SDKs.",
        "mitigation_commands": [
            "adb shell getenforce",
            "adb shell getprop ro.build.version.security_patch"
        ]
    },

    # IOS PLATFORM
    {
        "threat_id": "THREAT-IOS-001",
        "name": "LightSpy & Pegasus Modular Surveillance Chain",
        "platform": "ios",
        "stage": "active",
        "cve": "CVE-2024-23222",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "affected_versions": "iOS 16.x, iOS 17.0 to 17.2",
        "description": "Active zero-click spyware campaign delivered via iMessage and Safari WebKit zero-days. Bypasses BlastDoor sandbox, establishing kernel-level rootkit to harvest WhatsApp, mic audio, and GPS coordinates.",
        "indicators": ["Sysdiagnose showing unexpected crashtracer records", "Traffic to dynamic Fast-Flux C2 domains"],
        "mitigation_procedure": "1. Enable Apple Lockdown Mode (reduces attack surface by disabling WebKit JIT, incoming message attachments, and FaceTime invites from unknown senders).\n2. Update device immediately to iOS 17.5+ or 18.x.\n3. Regularly run MVT (Mobile Verification Toolkit) forensic analysis on sysdiagnose logs.",
        "mitigation_commands": [
            "mvt-ios check-backup --output /tmp/mvt_results /path/to/backup",
            "Enable 'Lockdown Mode' in Settings > Privacy & Security"
        ]
    },
    {
        "threat_id": "THREAT-IOS-002",
        "name": "CoreGraphics & ImageIO Buffer Overflow Exploit",
        "platform": "ios",
        "stage": "resolved",
        "cve": "CVE-2023-41064",
        "cvss": 8.8,
        "severity": "HIGH",
        "affected_versions": "iOS 16.6 and earlier",
        "description": "Vulnerability in ImageIO framework where processing a maliciously crafted PassKit / WebP image resulted in arbitrary code execution without user interaction.",
        "indicators": ["ImageIO memory corruption logs in mobile_watchdog"],
        "mitigation_procedure": "1. Mitigated by updating to iOS 16.6.1 / iOS 17.0.\n2. BlastDoor hardening deployed by Apple to isolate image rendering.",
        "mitigation_commands": [
            "Verify iOS Version >= 16.6.1 in Settings > General > About"
        ]
    }
]


def seed_threat_data(db):
    """Seed threat lifecycle data and RAG knowledge chunks if empty."""
    # 1. Threat lifecycle
    threat_col = db.threat_lifecycle
    if threat_col.count_documents({}) == 0:
        for item in INITIAL_THREATS:
            doc = dict(item)
            doc["created_at"] = utc_now()
            doc["last_updated"] = utc_now()
            threat_col.insert_one(doc)

    # 2. Knowledge chunks for RAG
    knowledge_col = db.knowledge
    from rag_engine import generate_embedding
    if knowledge_col.count_documents({"doc_id": {"$regex": "^THREAT-"}}) == 0:
        for threat in INITIAL_THREATS:
            text_block = (
                f"Threat: {threat['name']} (ID: {threat['threat_id']})\n"
                f"Platform: {threat['platform'].upper()} | Stage: {threat['stage'].upper()} | Severity: {threat['severity']} (CVSS {threat['cvss']})\n"
                f"Vulnerability: {threat['cve']} affecting {threat['affected_versions']}\n"
                f"Description: {threat['description']}\n"
                f"Detection Indicators: {', '.join(threat['indicators'])}\n"
                f"Mitigation Procedure: {threat['mitigation_procedure']}\n"
                f"Remediation Commands:\n" + "\n".join(threat['mitigation_commands'])
            )
            # Chunking
            emb = generate_embedding(text_block)
            knowledge_col.insert_one({
                "doc_id": threat["threat_id"],
                "title": threat["name"],
                "platform": threat["platform"],
                "stage": threat["stage"],
                "severity": threat["severity"],
                "chunk_index": 0,
                "text": text_block,
                "embedding": emb,
                "created_at": utc_now()
            })

    # 3. Seed Curriculum NoSQL Labs (Labs 1-18) into Knowledge Vector Store
    if knowledge_col.count_documents({"doc_id": {"$regex": "^EXP-LAB"}}) == 0:
        try:
            import sys
            cti_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "CTI_Fusion_Center_Updated", "CTI_Fusion_Center_Docker_Advanced_Checked", "cti_fusion_center_docker_keyless"))
            if cti_path not in sys.path:
                sys.path.insert(0, cti_path)
            from labs_xai import LABS_XAI

            for lab_id, lab_data in LABS_XAI.items():
                doc_id = f"EXP-{lab_id.replace(' ', '-').replace('.', '_').upper()}"
                text_block = (
                    f"Lab Experiment: {lab_id} - {lab_data.get('title')}\n"
                    f"Category: {lab_data.get('category')} | Core NoSQL Concept: {lab_data.get('concept')}\n"
                    f"What Happened in Experiment:\n{lab_data.get('what_happened')}\n"
                    f"Engine Internals & Mechanics:\n{lab_data.get('engine_internals')}\n"
                    f"Enterprise Impact:\n{lab_data.get('enterprise_impact')}\n"
                    f"{lab_data.get('short_note')}"
                )
                emb = generate_embedding(f"{lab_id} {lab_data.get('title')} {lab_data.get('concept')} {lab_data.get('what_happened')}")
                knowledge_col.insert_one({
                    "doc_id": doc_id,
                    "title": lab_data.get("title"),
                    "platform": "cross-platform",
                    "stage": "resolved",
                    "severity": "EDUCATIONAL",
                    "category": lab_data.get("category"),
                    "chunk_index": 0,
                    "text": text_block,
                    "lab_id": lab_id,
                    "concept": lab_data.get("concept"),
                    "what_happened": lab_data.get("what_happened"),
                    "engine_internals": lab_data.get("engine_internals"),
                    "enterprise_impact": lab_data.get("enterprise_impact"),
                    "short_note": lab_data.get("short_note"),
                    "embedding": emb,
                    "created_at": utc_now()
                })
        except Exception:
            pass
