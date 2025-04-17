import os
import json
from datetime import datetime
from utils.flatten import flatten_dict
from utils.mitre_index import get_investigation_tips
from triage.field_explanations import get_field_explanation
from triage.recommend import recommend_response

EXPORT_DIR = "exports"
os.makedirs(EXPORT_DIR, exist_ok=True)

HTML_HEAD = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SOCscribe Report</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f9f9f9; padding: 20px; }
    h1 { color: #003366; }
    .alert { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 0 5px #ccc; }
    .severity-High { border-left: 6px solid red; }
    .severity-Medium { border-left: 6px solid orange; }
    .severity-Low { border-left: 6px solid green; }
    .meta { font-size: 0.9em; color: #666; }
    .field { margin: 5px 0; }
    .field span.key { font-weight: bold; }
    .reason { font-style: italic; font-size: 0.85em; color: #444; margin-top: 5px; }
    details { margin-top: 10px; }
    summary { cursor: pointer; font-weight: bold; }
    ul { margin-top: 5px; }
  </style>
</head>
<body>
<h1>SOCscribe - Alert Report</h1>
"""

HTML_FOOT = """
</body>
</html>
"""

def export_alerts(alerts, output_path):
    html = HTML_HEAD

    for alert in alerts:
        rule = alert.get("rule", {})
        desc = rule.get("description", "No description")
        timestamp = alert.get("timestamp", "Unknown")
        severity = alert.get("_severity_label", "Low")
        reason = alert.get("_severity_reason", "")
        mitre_id = rule.get("mitre", {}).get("id", "-")
        tactic = rule.get("mitre", {}).get("tactic", "Unknown")
        technique = rule.get("mitre", {}).get("technique", "Unknown")

        # Flatten all fields
        flat = flatten_dict(alert)

        html += f"<div class='alert severity-{severity}'>"
        html += f"<h3>{desc}</h3>"
        html += f"<p class='meta'>🕒 {timestamp} | 🧠 MITRE: {tactic} – {technique} (<a href='https://attack.mitre.org/techniques/{mitre_id}'>[{mitre_id}]</a>)</p>"
        html += f"<p class='meta'>🚨 Severity: <strong>{severity}</strong></p>"
        if reason:
            html += f"<p class='reason'>Reason: {reason}</p>"

        # Investigation steps
        tips = get_investigation_tips(mitre_id)
        html += "<details><summary>🧪 Investigation Guidance</summary><ul>"
        for item in tips["what"]:
            html += f"<li>{item}</li>"
        for item in tips["where"]:
            html += f"<li><em>{item}</em></li>"
        html += "</ul></details>"

        # All fields
        html += "<details><summary>🔍 Full Alert Details</summary>"
        for key, value in flat.items():
            explanation = get_field_explanation(key)
            html += f"<div class='field'><span class='key'>{key}:</span> {value}<br><em>{explanation}</em></div>"
        html += "</details>"

        # Recommendations
        html += "<details><summary>🎯 Recommended Actions</summary><ul>"
        for line in recommend_response(alert, return_text=True).splitlines():
            html += f"<li>{line}</li>"
        html += "</ul></details>"

        html += "</div>"

    html += HTML_FOOT
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
