import os
import json
from utils.enrich import enrich_ip
from triage.recommend import recommend_response
from triage.field_explanations import get_field_explanation

try:
    from utils.enrich import enrich_virustotal
except ImportError:
    enrich_virustotal = None

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
        return "<span style='color:red;font-weight:bold'>🔴 High</span>"
    elif level >= 6:
        return "<span style='color:orange;font-weight:bold'>🟠 Medium</span>"
    else:
        return "<span style='color:green;font-weight:bold'>🟢 Low</span>"

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
    blocks = ""
    flat = flatten_json(alert)

    for key, value in flat.items():
        explanation = get_field_explanation(key)
        highlight = generate_highlight_comment(key, value)
        comment_html = f"<br/><em style='color:red'>{highlight}</em>" if highlight else ""
        blocks += f"""
        <p><strong>{key}:</strong> {value}
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
    # Summarize
    total = len(alerts)
    high, medium, low, mitre_hits = 0, 0, 0, 0
    for a in alerts:
        lvl = int(a.get("rule", {}).get("level", 0))
        mitre_id = str(a.get("rule", {}).get("mitre", {}).get("id", "")).lower()
        if lvl >= 10: high += 1
        elif lvl >= 6: medium += 1
        else: low += 1
        if any(x in mitre_id for x in ["t1059", "t1105", "t1547"]): mitre_hits += 1

    html = f"""
    <html>
    <head>
        <title>SOCscribe Alert Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
            .panel {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px #ccc; margin-bottom: 20px; }}
            h2 {{ color: #003366; }}
            h3 {{ color: #006699; }}
            code {{ background: #eee; padding: 2px 4px; border-radius: 4px; }}
            em {{ color: #666; font-size: 0.9em; }}
            details {{ margin-top: 5px; font-size: 0.9em; }}
            summary {{ cursor: pointer; color: #444; }}
            .tag {{ font-weight: bold; padding: 2px 6px; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <h1>SOCscribe Alerts Report</h1>
        <div class="panel">
            <h2>📊 Summary Dashboard</h2>
            <p><strong>Total Alerts:</strong> {total}</p>
            <p><strong>🔴 High Severity:</strong> {high}</p>
            <p><strong>🟠 Medium Severity:</strong> {medium}</p>
            <p><strong>🟢 Low Severity:</strong> {low}</p>
            <p><strong>🧠 MITRE TTP Hits (e.g., T1059, T1105):</strong> {mitre_hits}</p>
        </div>
    """

    for alert in alerts:
        rule = alert.get("rule", {})
        description = rule.get("description", "No description")
        alert_id = alert.get("id", "Unknown")
        level = int(rule.get("level", 0))
        severity_tag = generate_severity_tag(level)

        html += f"""
        <div class="panel">
            <h2>🚨 Alert ID: {alert_id}</h2>
            <h3>{description} — {severity_tag}</h3>
        """

        html += generate_field_blocks(alert)

        html += "<h3>🎯 Recommended Actions</h3><ul>"
        recs = generate_custom_recommendations(alert)
        for r in recs:
            html += f"<li>{r}</li>"
        html += "</ul></div>"

    html += "</body></html>"

    with open(output_path, "w") as f:
        f.write(html)
