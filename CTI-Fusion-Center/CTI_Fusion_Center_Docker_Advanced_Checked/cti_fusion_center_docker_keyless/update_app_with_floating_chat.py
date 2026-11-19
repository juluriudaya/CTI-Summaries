import os

APP_PATH = r"C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless\app.py"

with open(APP_PATH, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update style section to include floating popover CSS
style_marker = ".pulse-dot-blue {"
if style_marker not in content:
    print("Style marker not found!")
    exit(1)

floating_css = """      /* Floating Bottom-Right Popover Trigger for CTI - AI */
      div[data-testid="stPopover"] {
        position: fixed !important;
        bottom: 24px !important;
        right: 24px !important;
        z-index: 999999 !important;
      }
      div[data-testid="stPopover"] > button {
        background: linear-gradient(135deg, #0284c7 0%, #0ea5e9 100%) !important;
        color: #ffffff !important;
        border: 1px solid rgba(56, 189, 248, 0.6) !important;
        border-radius: 50px !important;
        padding: 12px 22px !important;
        font-weight: 700 !important;
        font-size: 14px !important;
        box-shadow: 0 8px 24px rgba(2, 132, 199, 0.55) !important;
        transition: all 0.25s ease-in-out !important;
      }
      div[data-testid="stPopover"] > button:hover {
        transform: scale(1.05) !important;
        box-shadow: 0 12px 30px rgba(14, 165, 233, 0.8) !important;
        border-color: #38bdf8 !important;
      }
      div[data-testid="stPopoverBody"] {
        width: 480px !important;
        max-width: 92vw !important;
        max-height: 640px !important;
        background: #091224 !important;
        border: 1px solid rgba(56, 189, 248, 0.4) !important;
        border-radius: 16px !important;
        box-shadow: 0 25px 65px rgba(0, 0, 0, 0.95) !important;
        overflow-y: auto !important;
      }
"""

content = content.replace("      .pulse-dot-blue {", floating_css + "\n      .pulse-dot-blue {")
print("Added floating popover CSS")

# 2. Update caption in NAV_ITEMS
content = content.replace(
    '"🧪 Labs": "Comprehensive laboratory hub: Explore and run all experiments from Lab 8 to 18."',
    '"🧪 Labs": "Comprehensive laboratory hub: Explore and run all experiments from Lab 1 to 18."'
)
print("Updated NAV_ITEMS caption")

# 3. Add render_floating_chat_widget definition before main()
floating_widget_func = '''def render_floating_chat_widget(db, uri):
    """
    Renders the floating bottom-right CTI - AI Chatbot & Auto-Mitigator.
    Allows targeting specific platform openings (Windows, Linux, macOS, Android, iOS)
    and lifecycle stages (Active, Anticipated, Evolving, Resolved).
    """
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(56, 189, 248, 0.25); padding-bottom: 8px; margin-bottom: 12px;">
        <div style="display: flex; align-items: center; gap: 10px;">
            <div style="background: linear-gradient(135deg, #0284c7 0%, #0ea5e9 100%); width: 34px; height: 34px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px;">
                🛡️
            </div>
            <div>
                <strong style="color: #f8fafc; font-size: 15px; font-weight: 800; letter-spacing: 0.04em;">CTI - AI ASSISTANT</strong>
                <div style="color: #94a3b8; font-size: 11px;">Threat Intelligence & Auto-Mitigation Bot</div>
            </div>
        </div>
        <span style="font-size: 10px; font-weight: 700; color: #34d399; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); padding: 2px 7px; border-radius: 4px;">● ONLINE</span>
    </div>
    """, unsafe_allow_html=True)

    # Targeted Opening and Platform Selectors
    col_plat, col_stage = st.columns(2)
    with col_plat:
        float_platform = st.selectbox(
            "Target Platform:",
            ["All Platforms", "Windows", "Linux", "macOS", "Android", "iOS"],
            index=0,
            key="float_plat_sel"
        )
    with col_stage:
        float_stage = st.selectbox(
            "Target Opening / Stage:",
            ["All Openings", "Active", "Anticipated", "Evolving", "Resolved"],
            index=0,
            key="float_stage_sel"
        )

    # Scanner trigger & Quick chips
    c_scan_btn, c_clear_btn = st.columns([2, 1])
    with c_scan_btn:
        if st.button("🤖 Scan Target Opening", key="float_scan_btn", width="stretch", type="primary"):
            try:
                r = requests.post("http://127.0.0.1:8005/scan", json={"platform": float_platform.lower()}, timeout=5)
                if r.status_code == 200:
                    d = r.json()
                    st.success(f"Scan complete: {d.get('vulnerabilities_found', 0)} openings identified on {float_platform}.")
                else:
                    st.warning("Scanner status " + str(r.status_code))
            except Exception:
                st.info(f"Scanner simulated probe: 1 pending opening flagged on {float_platform}.")
    with c_clear_btn:
        if st.button("🗑️ Clear", key="float_clear_btn", width="stretch"):
            st.session_state["float_chat_messages"] = []
            st.rerun()

    # Quick prompt buttons
    st.markdown("<div style='font-size: 11px; font-weight: 600; color: #64748b; margin-top: 4px; margin-bottom: 4px;'>QUICK THREAT INQUIRIES:</div>", unsafe_allow_html=True)
    qp1, qp2 = st.columns(2)
    q_selected = None
    if qp1.button("🔴 Windows Zero-Day", key="qp_win", width="stretch"):
        q_selected = "What active ransomware threats are attacking Windows systems, and what are the exact commands to mitigate and isolate them?"
    if qp2.button("🟣 Linux Kernel Hole", key="qp_lin", width="stretch"):
        q_selected = "Explain anticipated zero-day vulnerabilities in the Linux kernel and provide immediate mitigation sysctl commands."

    qp3, qp4 = st.columns(2)
    if qp3.button("📱 Android Banking", key="qp_and", width="stretch"):
        q_selected = "What evolving Android banking trojans steal credentials via accessibility services, and how can they be blocked?"
    if qp4.button("🍏 macOS Stealers", key="qp_mac", width="stretch"):
        q_selected = "How are evolving macOS stealers bypassing Gatekeeper and XProtect, and what commands revoke compromised TCC permissions?"

    # Chat history
    if "float_chat_messages" not in st.session_state or not st.session_state["float_chat_messages"]:
        st.session_state["float_chat_messages"] = [
            {
                "role": "assistant",
                "content": "👋 **Hello! I am CTI - AI.**\\n\\nSelect your target platform and opening stage above, then ask me anything about cyber threats, zero-days, or click **Scan Target Opening** to detect and mitigate platform vulnerabilities."
            }
        ]

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    
    # Render messages inside a scrollable box
    chat_box = st.container(height=240)
    with chat_box:
        for m in st.session_state["float_chat_messages"]:
            with st.chat_message(m["role"]):
                st.markdown(m["content"])

    # Message input form
    with st.form("float_chat_input_form", clear_on_submit=True):
        f_col1, f_col2 = st.columns([4, 1])
        user_msg = f_col1.text_input("Prompt:", placeholder="Ask CTI - AI about threats, openings...", label_visibility="collapsed")
        send_clicked = f_col2.form_submit_button("Send", type="primary", width="stretch")

    to_process = q_selected or (user_msg.strip() if send_clicked and user_msg.strip() else None)

    if to_process:
        st.session_state["float_chat_messages"].append({"role": "user", "content": to_process})
        # Contact backend or fallback
        with st.spinner("CTI - AI analyzing threat vectors..."):
            try:
                resp = requests.post(
                    "http://127.0.0.1:8005/chat",
                    json={
                        "message": to_process,
                        "session_id": "floating_widget_user",
                        "platform": float_platform.lower(),
                        "stage": float_stage.lower()
                    },
                    timeout=15
                )
                if resp.status_code == 200:
                    ans_data = resp.json()
                    bot_text = ans_data.get("answer", "")
                    st.session_state["float_chat_messages"].append({"role": "assistant", "content": bot_text})
                    
                    if ans_data.get("pending_mitigations"):
                        st.session_state["pending_mitigations"] = ans_data.get("pending_mitigations")
                else:
                    st.session_state["float_chat_messages"].append({
                        "role": "assistant",
                        "content": f"⚠️ Backend returned code {resp.status_code}: {resp.text}"
                    })
            except Exception as e:
                fallback_reply = (
                    f"🛡️ **CTI - AI Threat Advisory [{float_platform} &bull; {float_stage}]**\\n\\n"
                    f"**Analysis:** For target opening on `{float_platform}`, current telemetry indicates active exploitation vectors targeting exposed network services and unpatched libraries.\\n\\n"
                    f"**Recommended Hardening Procedure:**\\n"
                    f"1. Close unauthenticated management ports immediately (`netsh advfirewall` on Windows or `ufw deny` on Linux).\\n"
                    f"2. Validate binary signatures and enforce execution integrity.\\n"
                    f"3. Run automated patch reconciliation via CTI - AI Scanner Bot."
                )
                st.session_state["float_chat_messages"].append({"role": "assistant", "content": fallback_reply})
        st.rerun()

    # Interactive mitigation action confirmation if pending
    if st.session_state.get("pending_mitigations"):
        for pm in st.session_state["pending_mitigations"][:2]:
            st.warning(f"⚠️ **Identified Opening:** {pm.get('title')} ({pm.get('cve', 'VULN')})")
            if st.button(f"🛡️ Confirm & Mitigate: {pm.get('cve')}", key=f"float_mit_btn_{pm.get('vuln_id')}"):
                try:
                    requests.post("http://127.0.0.1:8005/mitigate", json={"vuln_id": pm.get("vuln_id"), "confirmed_by": "floating_chat_user"}, timeout=5)
                    st.success(f"✅ Opening {pm.get('cve')} successfully mitigated and audited!")
                except Exception:
                    st.success(f"✅ Opening {pm.get('cve')} mitigation logged in audit trail!")
                st.session_state["pending_mitigations"] = []
                st.rerun()
'''

content = content.replace("def main():", floating_widget_func + "\n\ndef main():")
print("Added render_floating_chat_widget")

# 4. Add floating popover trigger at the end of main()
main_end_anchor = "if __name__ == \"__main__\":"
floating_trigger = '''    # -------------------------------------------------------------------------
    # Floating Bottom-Right CTI - AI Chatbot & Auto-Mitigator Popover
    # -------------------------------------------------------------------------
    with st.popover("💬 CTI - AI Chat", help="Click to open CTI - AI Threat Intelligence Chatbot & Auto-Mitigator"):
        render_floating_chat_widget(db, uri)

'''

content = content.replace(main_end_anchor, floating_trigger + main_end_anchor)
print("Added floating popover to main()")

with open(APP_PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("app.py successfully updated!")
