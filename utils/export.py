
def calculate_severity(alert):
    rule = alert.get("rule", {})
    flat = flatten_json(alert)

    desc = rule.get("description", "").lower()
    mitre_id = str(rule.get("mitre", {}).get("id", "")).lower()
    fired = int(rule.get("firedtimes", 0))
    cmd = flat.get("data.win.eventdata.commandLine", "").lower()
    parent = flat.get("data.win.eventdata.parentImage", "").lower()
    image = flat.get("data.win.eventdata.image", "").lower()
    logon_type = flat.get("data.win.eventdata.logonType", "")

    high_tactics = ["t1059", "t1105", "t1547", "t1021", "t1218", "t1566", "t1055", "t1112"]
    if any(mitre_id.startswith(tid) for tid in high_tactics):
        return 10

    if any(tool in image for tool in ["rundll32", "regsvr32", "mshta", "wmic", "powershell", "cmd.exe"]):
        return 9

    if logon_type in ["3", "10"]:
        return 8

    if fired >= 5:
        return 7

    if any(x in cmd for x in ["invoke-", "downloadfile", "bypass", "base64"]):
        return 7

    if any(x in parent for x in ["powershell", "wscript", "cscript"]):
        return 6

    return int(rule.get("level", 0))


import os
import json
from utils.enrich import enrich_ip
from triage.recommend import recommend_response
from triage.field_explanations import get_field_explanation
from utils.mitre_index import get_investigation_tips

def flatten_json(y, parent_key='', sep='.'):
    items = []
    for k, v in y.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_json(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def generate_severity_tag(level):
    if level >= 10:
        return ("high", "<span style='color:red;font-weight:bold'>🔴 High</span>")
    elif level >= 6:
        return ("medium", "<span style='color:orange;font-weight:bold'>🟠 Medium</span>")
    else:
        return ("low", "<span style='color:green;font-weight:bold'>🟢 Low</span>")

def generate_highlight_comment(key, value):
    v = str(value).lower()
    if key == "rule.firedtimes" and int(value) > 5:
        return "🚨 Repeated trigger — could be scanning or brute-force attack."
    if key == "rule.level" and int(value) >= 10:
        return "🔥 Critical alert — treat as high-severity incident."
    if "commandline" in key and any(cmd in v for cmd in ["powershell", "cmd.exe", "wscript", "mshta", "base64"]):
        return "⚠️ Suspicious execution — script or obfuscated command detected."
    if "image" in key and any(tool in v for tool in ["powershell", "rundll32", "regsvr32", "cmd.exe"]):
        return "🔍 Known LOLBin or attack binary used — review process lineage."
    if key.endswith("logonType") and str(value) == "10":
        return "🔐 RDP logon detected — verify legitimacy."
    if key.endswith("logonType") and str(value) == "3":
        return "🔐 Network logon — often used for lateral movement."
    if "targetFilename" in key:
        return "📦 File drop observed — may indicate malware delivery."
    if "description" in key and "logon failure" in v:
        return "🛑 Failed login attempt — possible brute force."
    if any(tid in v for tid in ["t1059", "t1105", "t1547", "t1021", "t1218", "t1566"]):
        return "🧠 Mapped to high-risk MITRE technique — review associated behavior."
    return None

def generate_field_blocks(alert):
    flat = flatten_json(alert)
    blocks = ""
    for key, value in flat.items():
        explanation = get_field_explanation(key)
        comment = generate_highlight_comment(key, value)
        comment_html = f"<br/><em style='color:red'>{comment}</em>" if comment else ""
        blocks += f"""
        <p><strong title="{explanation}">{key}:</strong> {value}
        <details><summary>What does this mean?</summary>
        <em>{explanation}{comment_html}</em>
        </details></p>
        """
    return blocks

def generate_custom_recommendations(alert):
    recs = []
    flat = flatten_json(alert)
    rule = alert.get("rule", {})
    mitre = rule.get("mitre", {})
    level = int(rule.get("level", 0))
    fired = int(rule.get("firedtimes", 0))
    description = rule.get("description", "").lower()
    cmd = flat.get("data.win.eventdata.commandLine", "").lower()
    img = flat.get("data.win.eventdata.image", "").lower()

    if level >= 10:
        recs.append("🔥 Critical severity — escalate immediately to senior analyst or IR team.")
    if fired > 5:
        recs.append("🚨 Rule triggered frequently — check for brute-force, scan, or automated script.")
    if "powershell" in cmd or "cmd.exe" in cmd:
        recs.append("🧪 Analyze PowerShell/command line payload — possible obfuscation or post-exploitation.")
    if any(b in img for b in ["rundll32", "regsvr32", "mshta"]):
        recs.append("⚠️ LOLBin used — check for payload download or privilege escalation.")
    if "t1059" in str(mitre.get("id", "")).lower():
        recs.append("🧠 MITRE T1059: Scripting — investigate execution chain and user context.")
    if "t1105" in str(mitre.get("id", "")).lower():
        recs.append("📡 MITRE T1105: File transfer — monitor outbound traffic and dropped files.")
    if "t1547" in str(mitre.get("id", "")).lower():
        recs.append("🛠️ MITRE T1547: Persistence — inspect autoruns, startup, registry modifications.")
    if "logon failure" in description:
        recs.append("🛡 Check source IP and account — possible password spray or brute-force.")
    if flat.get("data.win.eventdata.logonType") == "10":
        recs.append("🔐 Remote desktop session detected — confirm session legitimacy.")
    if not recs:
        recs.append("✅ No critical behavior detected — proceed with standard log review.")
    return recs

def export_alerts(alerts, output_path):
    total = len(alerts)
    high = medium = low = mitre_hits = 0
    panels = []

    for a in alerts:
        lvl = int(a.get("rule", {}).get("level", 0))
        mitre_id = str(a.get("rule", {}).get("mitre", {}).get("id", "")).lower()
        if lvl >= 10: high += 1
        elif lvl >= 6: medium += 1
        else: low += 1
        if mitre_id.startswith("t1"): mitre_hits += 1

        rule = a.get("rule", {})
        desc = rule.get("description", "No description")
        alert_id = a.get("id", "Unknown")
        severity_key, severity_tag = generate_severity_tag(lvl)

        panel = f"""<div class="panel alert" data-severity="{severity_key}">
            <h2>🚨 Alert ID: {alert_id}</h2>
            <h3>{desc} — {severity_tag}</h3>
            {generate_field_blocks(a)}
            <h3>🎯 Recommended Actions</h3>
            <ul>{''.join(f"<li>{r}</li>" for r in generate_custom_recommendations(a))}</ul>
        """

        mitre_id_upper = str(rule.get("mitre", {}).get("id", "")).upper()
        if mitre_id_upper:
            tips = get_investigation_tips(mitre_id_upper)
            technique_id = tips['title'].split(' – ')[0].strip()
            mitre_link = f"https://attack.mitre.org/techniques/{technique_id}"
            panel += f"""
            <h3>🧠 MITRE Technique: <a href="{mitre_link}" target="_blank">{tips['title']}</a></h3>
            <details><summary>What to Investigate</summary><ul>
                {''.join(f"<li>{w}</li>" for w in tips['what'])}
            </ul></details>
            <details><summary>Where to Check</summary><ul>
                {''.join(f"<li>{w}</li>" for w in tips['where'])}
            </ul></details>
            """

        panel += "</div>"
        panels.append(panel)

    html = f"""<!DOCTYPE html>
<html>
<head>
  <title>SOCscribe Report</title>
  <style>
    body {{ font-family: Arial; background: #f5f5f5; padding: 20px; }}
    .panel {{ background: white; border-radius: 8px; box-shadow: 0 0 5px #ccc; padding: 20px; margin-bottom: 20px; }}
    h2 {{ color: #003366; }}
    h3 {{ color: #006699; }}
    details {{ margin-top: 8px; }}
    summary {{ cursor: pointer; }}
    strong[title] {{ border-bottom: 1px dotted #999; cursor: help; }}
    .filter-bar {{ background: #fff; padding: 10px 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 0 5px #ccc; }}
    .filter-bar button {{ margin-right: 10px; padding: 6px 12px; }}
    .filter-bar input {{ padding: 6px; width: 200px; }}
    .hidden {{ display: none; }}
  </style>
</head>
<body>
  <h1>SOCscribe Alert Report</h1>

  <div class="filter-bar">
    <button onclick="filterBySeverity('high')">🔴 High</button>
    <button onclick="filterBySeverity('medium')">🟠 Medium</button>
    <button onclick="filterBySeverity('low')">🟢 Low</button>
    <button onclick="resetFilters()">Reset</button>
    <input type="text" id="searchBox" placeholder="Search MITRE ID or content..." onkeyup="searchText()">
  </div>

  <div class="panel">
    <h2>📊 Summary</h2>
    <p><strong>Total Alerts:</strong> {total}</p>
    <p><strong>🔴 High:</strong> {high}</p>
    <p><strong>🟠 Medium:</strong> {medium}</p>
    <p><strong>🟢 Low:</strong> {low}</p>
    <p><strong>🧠 MITRE-related:</strong> {mitre_hits}</p>
  </div>

  <div id="alert-container">
    {''.join(panels)}
  </div>

  <script>
    function filterBySeverity(sev) {{
      const all = document.querySelectorAll('.panel.alert');
      all.forEach(el => {{
        if (el.dataset.severity === sev) {{
          el.classList.remove('hidden');
        }} else {{
          el.classList.add('hidden');
        }}
      }});
    }}

    function resetFilters() {{
      document.querySelectorAll('.panel.alert').forEach(el => el.classList.remove('hidden'));
      document.getElementById('searchBox').value = "";
    }}

    function searchText() {{
      const q = document.getElementById('searchBox').value.toLowerCase();
      document.querySelectorAll('.panel.alert').forEach(el => {{
        el.textContent.toLowerCase().includes(q)
          ? el.classList.remove('hidden')
          : el.classList.add('hidden');
      }});
    }}
  </script>
</body>
</html>
"""


    with open(output_path, "w") as f:
        f.write(html)
