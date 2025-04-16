import os
import json
from datetime import datetime
from triage.recommend import recommend_response
from triage.field_explanations import get_field_explanation
from utils.mitre_index import get_investigation_tips
from utils.flatten import flatten_dict as flatten_json  # alias fix

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
        return "🚨 Repeated trigger — could be scanning or brute-force."
    if "commandline" in key and any(x in v for x in ["powershell", "cmd.exe", "base64", "wscript"]):
        return "⚠️ Suspicious script-based execution detected."
    return None

def generate_field_blocks(alert):
    blocks = ""
    flat = flatten_json(alert)
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
    level = int(rule.get("level", 0))
    desc = rule.get("description", "").lower()

    if level >= 10:
        recs.append("🔥 Critical — escalate to IR team.")
    if flat.get("rule.firedtimes", 0) and int(flat["rule.firedtimes"]) > 5:
        recs.append("🚨 Repeated rule trigger — check for brute-force or automation.")
    if "powershell" in desc or "cmd" in desc:
        recs.append("🔍 Script engine used — investigate command and source.")
    if not recs:
        recs.append("✅ No critical behavior — review manually.")
    return recs

def export_alerts(alerts, output_path):
    total, high, medium, low, mitre_hits = 0, 0, 0, 0, 0
    tactic_map = {}

    for alert in alerts:
        total += 1
        rule = alert.get("rule", {})
        tactic = rule.get("mitre", {}).get("tactic", "Unknown")
        tactic_key = tactic.lower() if isinstance(tactic, str) else tactic[0].lower()

        lvl = int(rule.get("level", 0))
        mitre_id = rule.get("mitre", {}).get("id", "")
        if isinstance(mitre_id, list):  # 🔧 fix for list-type MITRE ID
            mitre_id = mitre_id[0] if mitre_id else ""
        if lvl >= 10: high += 1
        elif lvl >= 6: medium += 1
        else: low += 1
        if mitre_id: mitre_hits += 1

        alert["_severity"], alert["_severity_tag"] = generate_severity_tag(lvl)
        alert["_tactic"] = tactic_key
        alert["_mitre"] = mitre_id
        tactic_map.setdefault(tactic_key, []).append(alert)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SOCscribe Alert Report</title>
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
  <input type="date" id="startDate" onchange="filterByDate()">
  <input type="date" id="endDate" onchange="filterByDate()">
  <input type="text" id="searchBox" placeholder="Search MITRE or text..." onkeyup="searchText()">
</div>

<div class="panel">
  <h2>📊 Summary</h2>
  <p><strong>Total:</strong> {total} | 🔴 {high} | 🟠 {medium} | 🟢 {low} | 🧠 MITRE Alerts: {mitre_hits}</p>
</div>
"""

    for tactic, group in tactic_map.items():
        html += f"""<div class="panel"><h2>🧠 Tactic: {tactic.title()}</h2>"""
        for alert in group:
            ts = alert.get("timestamp", "")
            tag = alert["_severity_tag"]
            mitre = alert["_mitre"]
            aid = alert.get("id", "")
            desc = alert.get("rule", {}).get("description", "No description")

            html += f"""<div class="panel alert" data-severity="{alert['_severity']}" data-timestamp="{ts}" data-mitre="{mitre.lower()}">
                <h3>🚨 {desc} — {tag}</h3>
                <p><strong>Timestamp:</strong> {ts}</p>
                {generate_field_blocks(alert)}
                <h3>🎯 Recommended Actions</h3><ul>"""
            for r in generate_custom_recommendations(alert):
                html += f"<li>{r}</li>"
            html += "</ul>"

            if mitre:
                tips = get_investigation_tips(mitre)
                link = f"https://attack.mitre.org/techniques/{mitre}"
                html += f"""<h3>🧠 MITRE Technique: <a href="{link}" target="_blank">{tips['title']}</a></h3>"""
                html += "<details><summary>What to Investigate</summary><ul>"
                for w in tips["what"]:
                    html += f"<li>{w}</li>"
                html += "</ul></details>"
                html += "<details><summary>Where to Check</summary><ul>"
                for w in tips["where"]:
                    html += f"<li>{w}</li>"
                html += "</ul></details>"

            html += "</div>"
        html += "</div>"

    html += """
<script>
function filterBySeverity(sev) {
  document.querySelectorAll('.panel.alert').forEach(el => {
    el.classList.toggle('hidden', el.dataset.severity !== sev);
  });
}

function resetFilters() {
  document.querySelectorAll('.panel.alert').forEach(el => el.classList.remove('hidden'));
  document.getElementById('startDate').value = "";
  document.getElementById('endDate').value = "";
  document.getElementById('searchBox').value = "";
}

function filterByDate() {
  let start = new Date(document.getElementById('startDate').value);
  let end = new Date(document.getElementById('endDate').value);
  document.querySelectorAll('.panel.alert').forEach(el => {
    let ts = new Date(el.dataset.timestamp);
    el.classList.toggle('hidden', (start && ts < start) || (end && ts > end));
  });
}

function searchText() {
  const q = document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('.panel.alert').forEach(el => {
    el.classList.toggle('hidden', !el.textContent.toLowerCase().includes(q));
  });
}
</script>

</body></html>
"""

    with open(output_path, "w") as f:
        f.write(html)
