import os
import re

UI_PATH = r"C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless\labs_ui.py"

with open(UI_PATH, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add import labs_xai as lxai
if "import labs_xai as lxai" not in content:
    content = content.replace("import labs_engine as le", "import labs_engine as le\nimport labs_xai as lxai")
    print("Added import labs_xai as lxai")

# 2. Add XAI Master Explorer to render_master_runner
marker = "st.subheader(\"🏛️ Enterprise System Architecture Diagrams"
xai_block = '''    st.divider()
    lxai.render_xai_master_explorer()

    '''

if marker in content and "lxai.render_xai_master_explorer()" not in content:
    content = content.replace(marker, xai_block + marker)
    print("Added XAI master explorer to render_master_runner")

# 3. Add render_xai_card to each lab renderer
lab_renderers = [
    ("render_lab_1", "Lab 1"),
    ("render_lab_2", "Lab 2"),
    ("render_lab_3", "Lab 3"),
    ("render_lab_4", "Lab 4"),
    ("render_lab_5", "Lab 5"),
    ("render_lab_6", "Lab 6"),
    ("render_lab_7_1", "Lab 7.1"),
    ("render_lab_7_2", "Lab 7.2"),
    ("render_lab_8", "Lab 8"),
    ("render_lab_9", "Lab 9"),
    ("render_lab_10", "Lab 10"),
    ("render_lab_11", "Lab 11"),
    ("render_lab_12", "Lab 12"),
    ("render_lab_13", "Lab 13"),
    ("render_lab_14", "Lab 14"),
    ("render_lab_15", "Lab 15"),
    ("render_lab_16", "Lab 16"),
    ("render_lab_17", "Lab 17"),
    ("render_lab_18", "Lab 18"),
]

# For each lab, append lxai.render_xai_card(lab_id) before the next function starts
for func_name, lab_id in lab_renderers:
    # Find the def
    pattern = rf"(def {func_name}\([^\)]*\):[\s\S]*?)(?=\n\n(?:def render_|\Z))"
    match = re.search(pattern, content)
    if match:
        matched_text = match.group(1)
        if f'lxai.render_xai_card("{lab_id}")' not in matched_text:
            replacement = matched_text.rstrip() + f'\n    lxai.render_xai_card("{lab_id}")\n'
            content = content.replace(matched_text, replacement)
            print(f"Added XAI card to {func_name} ({lab_id})")

with open(UI_PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("labs_ui.py successfully updated with Explainable AI (XAI)!")
