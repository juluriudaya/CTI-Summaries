"""Streamlit Chat Frontend for CTI Chat Bot (Universal AI + Threat Intelligence + NoSQL Labs 1-18).

UI v3: hero header with live status pills, suggestion cards, polished chat bubbles,
organised sidebar, typing effect, and conversational mitigation cards.
"""

import os
import sys
import time
import requests
import streamlit as st

# Import Lab FAQs
cti_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "CTI_Fusion_Center_Updated", "CTI_Fusion_Center_Docker_Advanced_Checked", "cti_fusion_center_docker_keyless"))
if cti_dir not in sys.path:
    sys.path.insert(0, cti_dir)
try:
    from lab_faqs import LAB_COMMON_QUESTIONS
except Exception:
    LAB_COMMON_QUESTIONS = {}

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8005")

st.set_page_config(
    page_title="CTI Chat Bot — Universal AI & Threat Intelligence",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Styling
# -----------------------------------------------------------------------------
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');
  html, body, [class*="css"] { font-family: 'Inter', 'Segoe UI', sans-serif; }
  #MainMenu, footer { visibility: hidden; }
  header[data-testid="stHeader"] { background: transparent; }

  .stApp {
    background-color: #060b16;
    background-image:
      radial-gradient(ellipse 60% 40% at 10% 0%, rgba(59,130,246,0.16) 0%, transparent 60%),
      radial-gradient(ellipse 50% 40% at 95% 100%, rgba(16,185,129,0.10) 0%, transparent 60%);
  }
  .block-container { max-width: 1100px; padding-top: 1.4rem; padding-bottom: 6rem; }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a1326 0%, #050912 100%) !important;
    border-right: 1px solid rgba(59,130,246,0.18) !important;
  }
  [data-testid="stSidebar"] h3 { font-size: 12px !important; letter-spacing: .12em; text-transform: uppercase; color: #7dd3fc !important; margin-top: .4rem; }
  .brand { display:flex; align-items:center; gap:12px; margin: 2px 0 14px 0; }
  .brand-logo { width:42px; height:42px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:22px;
      background: linear-gradient(135deg,#2563eb,#06b6d4); box-shadow: 0 6px 18px rgba(6,182,212,.35); }
  .brand-name { color:#fff; font-weight:800; font-size:17px; letter-spacing:.04em; font-family:'JetBrains Mono',monospace; }
  .brand-sub { color:#38bdf8; font-size:10px; font-weight:700; letter-spacing:.14em; }

  /* Hero */
  .hero { padding: 18px 22px; border-radius: 18px; margin-bottom: 14px;
      background: linear-gradient(135deg, rgba(37,99,235,.16), rgba(15,23,42,.65) 55%, rgba(16,185,129,.10));
      border: 1px solid rgba(148,163,184,.16); box-shadow: 0 10px 30px rgba(0,0,0,.28); }
  .hero h1 { margin:0; font-size: 28px; font-weight: 800; color:#f8fafc; letter-spacing:-.01em; }
  .hero h1 span { background: linear-gradient(90deg,#60a5fa,#34d399); -webkit-background-clip:text; background-clip:text; color:transparent; }
  .hero p { margin:6px 0 12px 0; color:#94a3b8; font-size:14px; }
  .pill { display:inline-flex; align-items:center; gap:6px; padding:4px 11px; margin:0 6px 4px 0; border-radius:999px;
      font-size:11.5px; font-weight:600; border:1px solid; }
  .pill.ok   { color:#6ee7b7; background:rgba(16,185,129,.12); border-color:rgba(16,185,129,.35); }
  .pill.bad  { color:#fca5a5; background:rgba(239,68,68,.12);  border-color:rgba(239,68,68,.35); }
  .pill.info { color:#93c5fd; background:rgba(59,130,246,.12); border-color:rgba(59,130,246,.35); }
  .dot { width:7px; height:7px; border-radius:50%; background:currentColor; box-shadow:0 0 8px currentColor; }

  /* Section labels */
  .sec-label { font-size:11px; font-weight:700; letter-spacing:.14em; color:#64748b; margin: 14px 0 6px 2px; text-transform:uppercase; }

  /* Buttons */
  .stButton > button {
    border-radius: 12px; border: 1px solid rgba(148,163,184,.22);
    background: rgba(15,23,42,.7); color:#e2e8f0; font-weight:600; font-size:13px;
    transition: all .15s ease; min-height: 44px;
  }
  .stButton > button:hover { border-color:#38bdf8; color:#fff; background: rgba(14,165,233,.14); transform: translateY(-1px); box-shadow: 0 6px 16px rgba(14,165,233,.18); }
  .stButton > button[kind="primary"] { background: linear-gradient(135deg,#2563eb,#0891b2); border:none; color:#fff; }

  /* Chat */
  [data-testid="stChatMessage"] { background: rgba(15,23,42,.55); border:1px solid rgba(148,163,184,.12);
      border-radius: 16px; padding: 14px 16px; margin-bottom: 10px; }
  [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) { background: rgba(37,99,235,.14); border-color: rgba(59,130,246,.28); }
  [data-testid="stChatMessage"] h3 { font-size: 18px; margin-top: .2rem; }
  [data-testid="stChatMessage"] code { font-family:'JetBrains Mono',monospace; font-size:12.5px; }
  [data-testid="stChatMessage"] pre { border-radius: 12px; border: 1px solid rgba(148,163,184,.15); }
  [data-testid="stChatMessage"] table { font-size: 13px; }
  [data-testid="stChatInput"] { border-radius: 16px; }
  [data-testid="stChatInput"] textarea { font-size: 15px; }

  /* Suggestion cards */
  .card-note { color:#94a3b8; font-size:12px; margin-top:-2px; margin-bottom:6px; }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Live status (via backend so it works on host and inside Docker)
# -----------------------------------------------------------------------------
def fetch_health():
    try:
        return requests.get(f"{BACKEND_URL}/health", timeout=3).json()
    except Exception:
        return None


health = fetch_health()
backend_up = health is not None
ol_online = bool(health and health.get("ollama_online"))
ol_models = (health or {}).get("ollama_models", [])

if "messages" not in st.session_state:
    st.session_state["messages"] = []
if "dismissed_mitigations" not in st.session_state:
    st.session_state["dismissed_mitigations"] = set()


# -----------------------------------------------------------------------------
# Sidebar
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div class="brand">
      <div class="brand-logo">🤖</div>
      <div><div class="brand-name">CTI CHAT BOT</div><div class="brand-sub">UNIVERSAL AI · THREAT INTEL · LABS</div></div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("➕  New chat", width="stretch", type="primary"):
        st.session_state["messages"] = []
        st.rerun()

    st.markdown("### Context filters")
    selected_platform = st.selectbox("Target OS", ["All Platforms", "Windows", "Linux", "macOS", "Android", "iOS"], index=0,
                                     help="Narrows threat-intelligence answers to one operating system.")
    selected_stage = st.selectbox("Threat lifecycle", ["All Stages", "Active", "Anticipated", "Evolving", "Resolved"], index=0,
                                  help="Narrows threat-intelligence answers to one lifecycle stage.")

    st.markdown("### Security audit")
    st.caption("Audits open ports, vulnerable dependencies and system posture on this machine.")
    if st.button("⚡ Scan my system", width="stretch"):
        try:
            r = requests.post(f"{BACKEND_URL}/scan", json={"platform": selected_platform.lower()}, timeout=60)
            if r.status_code == 200:
                data = r.json()
                report_md = data.get("markdown_report")
                if not report_md:
                    from system_vulnerability_scanner import format_scan_report_markdown
                    report_md = format_scan_report_markdown(data)
                m = data.get("metrics", {})
                st.session_state["messages"].append({
                    "role": "assistant",
                    "content": (
                        "### 🛡️ System scan results\n\n"
                        f"* **Ports scanned:** {m.get('ports_scanned', 9)}\n"
                        f"* **Posture:** {m.get('overall_posture', 'AUDITED')}\n"
                        f"* **Findings:** {m.get('total_vulnerabilities', 0)} (synced to MongoDB)\n\n---\n\n" + report_md
                    ),
                })
                st.rerun()
            else:
                st.error("Scanner returned an error.")
        except Exception as exc:
            st.warning(f"Could not reach scanner service: {exc}")

    st.markdown("### Navigation")
    st.link_button("🛡️ CTI Operations Console (8502) ↗", "http://localhost:8502", use_container_width=True)

    st.markdown("### About this bot")
    st.caption("Runs 100% locally (no internet). It can't fetch live data such as weather, prices or news, "
               "and can occasionally be wrong — verify important facts.")
    st.caption(f"Backend: `{BACKEND_URL}`")


# -----------------------------------------------------------------------------
# Hero header with live status pills
# -----------------------------------------------------------------------------
llm_pill = (f'<span class="pill ok"><span class="dot"></span>LLM online · {ol_models[0]}</span>' if ol_online and ol_models
            else '<span class="pill ok"><span class="dot"></span>LLM online</span>' if ol_online
            else '<span class="pill bad"><span class="dot"></span>LLM offline · fallback engine</span>')
api_pill = ('<span class="pill ok"><span class="dot"></span>API connected</span>' if backend_up
            else '<span class="pill bad"><span class="dot"></span>API unreachable</span>')
st.markdown(f"""
<div class="hero">
  <h1>Ask anything. <span>Defend everything.</span></h1>
  <p style="font-size: 1.05rem; font-style: italic; opacity: 0.95;">“Security is not a product, but a process — and knowledge is your strongest perimeter.” — Bruce Schneier</p>
  {llm_pill}{api_pill}
  <span class="pill info">🔒 Private · runs locally</span>
  <a href="http://localhost:8502" target="_blank" style="text-decoration:none;" class="pill ok"><span class="dot"></span>🛡️ Operations Console (8502) ↗</a>
</div>
""", unsafe_allow_html=True)

quick_prompt = None

# -----------------------------------------------------------------------------
# Empty state: suggestion cards
# -----------------------------------------------------------------------------
landing = st.empty()
if not st.session_state["messages"]:
    with landing.container():
        st.markdown("<div class='sec-label'>Get started</div>", unsafe_allow_html=True)
        cards = [
            ("💡 Explain TCP", "Explain TCP: full form, the 3-way handshake and how it differs from UDP."),
            ("💻 Write Python code", "Write a Python function to check if a string is a palindrome, with an example."),
            ("🧮 Solve a math problem", "Solve 3x + 7 = 25 and explain each step."),
            ("🏢 Threat analysis", "Give me a threat analysis of the Flipkart website."),
            ("🔬 Explain Lab 5", "Explain Lab 5 in my experiments."),
            ("🛡️ Local vulnerabilities", "Show the local vulnerabilities detected on my system with CVE details and status."),
        ]
        for row in (cards[:3], cards[3:]):
            cols = st.columns(3)
            for col, (label, prompt) in zip(cols, row):
                if col.button(label, key=f"card_{label}", width="stretch"):
                    quick_prompt = prompt

        st.markdown("<div class='sec-label'>Platform threats</div>", unsafe_allow_html=True)
        t1, t2, t3, t4 = st.columns(4)
        if t1.button("🔴 Windows threats", width="stretch"):
            quick_prompt = "What active threats are impacting Windows systems right now, and what are the exact mitigation procedures?"
        if t2.button("🟣 Linux CVEs", width="stretch"):
            quick_prompt = "Explain anticipated zero-day vulnerabilities in the Linux kernel and provide mitigation commands."
        if t3.button("🟠 macOS backdoors", width="stretch"):
            quick_prompt = "How are evolving macOS stealers and LOLBin pipelines evading detection, and how do we neutralize them?"
        if t4.button("⚡ Live port scan", width="stretch"):
            quick_prompt = "Scan my system for cyber vulnerabilities and report exposed ports or CVEs."


# -----------------------------------------------------------------------------
# Lab selector (collapsible)
# -----------------------------------------------------------------------------
lab_catalog = ["None (General Mode)", "Lab 1", "Lab 2", "Lab 3", "Lab 4", "Lab 5", "Lab 6",
               "Lab 7.1", "Lab 7.2", "Lab 8", "Lab 9", "Lab 10", "Lab 11", "Lab 12",
               "Lab 13", "Lab 14", "Lab 15", "Lab 16", "Lab 17", "Lab 18"]
with st.expander("🔬 NoSQL Labs 1–18 · common viva questions", expanded=False):
    selected_lab_exp = st.selectbox("Choose an experiment", lab_catalog, index=0, key="chat_lab_selector_drop")
    if selected_lab_exp != "None (General Mode)":
        lab_faqs = LAB_COMMON_QUESTIONS.get(selected_lab_exp, [])
        if lab_faqs:
            st.caption(f"Most common questions for **{selected_lab_exp}** — click one to ask:")
            for i, q in enumerate(lab_faqs):
                if st.button(f"❓ {q}", key=f"chat_faq_{selected_lab_exp}_{i}", width="stretch"):
                    quick_prompt = q
        else:
            st.caption("No saved questions for this lab yet — just ask in the chat box.")

# -----------------------------------------------------------------------------
# Chat history
# -----------------------------------------------------------------------------
avatar_static = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "robot_avatar.png")
bot_avatar = avatar_static if os.path.exists(avatar_static) else "🤖"

for msg in st.session_state["messages"]:
    with st.chat_message(msg["role"], avatar="🧑‍💻" if msg["role"] == "user" else bot_avatar):
        st.markdown(msg["content"])


def type_out(text: str):
    """Typing effect (the answer is already complete; this only animates its display)."""
    for chunk in text.split(" "):
        yield chunk + " "
        time.sleep(0.008)


# -----------------------------------------------------------------------------
# Input + response
# -----------------------------------------------------------------------------
user_input = st.chat_input("Ask a question, analyze a threat, or explore a curriculum concept...")
active_input = quick_prompt or user_input

if active_input:
    landing.empty()
    st.session_state["messages"].append({"role": "user", "content": active_input})
    with st.chat_message("user", avatar="🧑‍💻"):
        st.markdown(active_input)

    with st.chat_message("assistant", avatar=bot_avatar):
        try:
            with st.spinner("Thinking… (local model, usually 5–20 seconds)"):
                resp = requests.post(
                    f"{BACKEND_URL}/chat",
                    json={"message": active_input, "session_id": "soc_analyst_session",
                          "platform": selected_platform.lower(), "stage": selected_stage.lower()},
                    timeout=120,
                )
            if resp.status_code == 200:
                data = resp.json()
                answer = data.get("answer", "No response generated.")
                backend = data.get("backend", "CTI-AI")
                latency = data.get("latency_ms", 0)
                context_chunks = data.get("context", [])

                if len(answer) < 6000:
                    st.write_stream(type_out(answer))
                else:
                    st.markdown(answer)
                st.caption(f"⚡ {backend} · {round(latency / 1000, 1)}s · {len(context_chunks)} knowledge chunks")

                if context_chunks:
                    with st.expander("🔍 Sources (MongoDB knowledge chunks)"):
                        for i, c in enumerate(context_chunks):
                            st.markdown(f"**{i+1}. {c.get('title')}** `(similarity {round(c.get('similarity', 0)*100, 1)}%)`")
                            st.code(c.get("text"), language="markdown")

                st.session_state["messages"].append({"role": "assistant", "content": answer})

                pending = [m for m in data.get("pending_mitigations", [])
                           if m.get("vuln_id") not in st.session_state["dismissed_mitigations"]]
                if pending:
                    st.info(f"⚠️ {len(pending)} vulnerability fix(es) are waiting for your approval.")
                    for m in pending[:2]:
                        c_info, c_ok, c_no = st.columns([2.5, 1, 0.9])
                        with c_info:
                            st.markdown(f"**{m.get('title')}** (`{m.get('cve')}`)")
                            st.caption(f"Fix: `{m.get('remediation_command')}`")
                        with c_ok:
                            if st.button("Approve fix", key=f"btn_mitigate_{m.get('vuln_id')}"):
                                mr = requests.post(f"{BACKEND_URL}/mitigate",
                                                   json={"vuln_id": m.get("vuln_id"), "confirmed_by": "analyst_chat_button"}, timeout=10)
                                if mr.status_code == 200:
                                    st.success(f"Mitigated {m.get('cve')} — logged in MongoDB.")
                                    st.rerun()
                        with c_no:
                            if st.button("Dismiss", key=f"btn_dism_{m.get('vuln_id')}"):
                                st.session_state["dismissed_mitigations"].add(m.get("vuln_id"))
                                st.rerun()
            else:
                err = f"Backend returned status {resp.status_code}: {resp.text}"
                st.error(err)
                st.session_state["messages"].append({"role": "assistant", "content": err})
        except Exception as exc:
            err = f"Couldn't reach the backend at `{BACKEND_URL}`. Make sure the API is running.\n\n`{exc}`"
            st.error(err)
            st.session_state["messages"].append({"role": "assistant", "content": err})
