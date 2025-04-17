import os
import json
from datetime import datetime
from utils.flatten import flatten_dict
from utils.mitre_index import get_investigation_tips
from triage.field_explanations import get_field_explanation
from triage.recommend import recommend_response
from utils.severity import get_mitre_severity

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
    .filters { margin-bottom: 20px; }
    .filters label { margin-right: 10px; }
    input, select { padding: 4px; margin-right: 10px; }
  </style>
</head>
<body>
<h1>SOCscribe - Alert Report</h1>

<div class="filters">
  <label>Severity:</label>
  <select id="severityFilter" onchange="applyFilters()">
    <option value="">All</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
  </select>

  <label>MITRE ID:</label>
  <input type="text" id="mitreFilter" placeholder="e.g., T1059" onkeyup="applyFilters()"/>

  <label>Date:</label>
  <input type="date" id="dateFilter" onchange="applyFilters()"/>

  <label>Keyword:</label>
  <input type="text" id="keywordFilter" placeholder="e.g., powershell" onkeyup="applyFilters()" />
</div>
"""

HTML_FOOT = """
<script>
function applyFilters() {
  const severity = document.getElementById("severityFilter").value;
  const mitre = document.getElementById("mitreFilter").value.toLowerCase();
  const date = document.getElementById("dateFilter").value;
  const keyword = document.getElementById("keywordFilter").value.toLowerCase();

  const alerts = document.querySelectorAll(".alert");
  alerts.forEach(alert => {
    const sev = alert.getAttribute("data-severity");
    const mitreText = alert.getAttribute("data-mitre");
    const time = alert.getAttribute("data-time");
    const content = alert.getAttribute("data-content");

    const matchSev = !severity || sev === severity;
    const matchMitre = !mitre || mitreText.toLowerCase().includes(mitre);
    const matchDate = !date || (time && time.startsWith(date));
    const matchKeyword = !keyword || content.includes(keyword);

    alert.style.display = (matchSev && matchMitre && matchDate && matchKeyword) ? "block" : "none";
  });
}
</script>
</body>
</html>
"""

def build_mitre_link(mid):
    if "." in mid:
        parent, sub = mid.split(".")
        sub = sub.zfill(3)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}"
    return f"https://attack.mitre.org/techniques/{mid}"

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
        flat = flatten_dict(alert)
        content_text = json.dumps(flat).lower()

        ids = mitre_id if isinstance(mitre_id, list) else [mitre_id]
        links = " ".join([f"<a href='{build_mitre_link(mid)}' target='_blank'>[{mid}]</a>" for mid in ids])

        html += f"<div class='alert severity-{severity}' data-severity='{severity}' data-mitre='{','.join(ids)}' data-time='{timestamp}' data-content='{content_text}'>"
        html += f"<h3>{desc}</h3>"
        html += f"<p><strong>🧠 What happened?</strong> {desc}</p>"
        html += f"<p><strong>🔍 Why it's important:</strong> {reason}</p>"
        html += f"<p class='meta'>🕒 {timestamp} | 🧠 MITRE: {tactic} – {technique} {links}</p>"
        html += f"<p class='meta'>🚨 Severity: <strong>{severity}</strong></p>"

        html += "<details><summary>🧪 Investigation Guidance</summary>"
        for mid in ids:
            tips = get_investigation_tips(mid)
            mitre_sev = get_mitre_severity(mid)
            color = "red" if mitre_sev == "High" else "orange" if mitre_sev == "Medium" else "green" if mitre_sev == "Low" else "gray"
            html += f"<h4><span style='color:{color}'>[{mitre_sev}]</span> {tips['title']}</h4><ul>"
            for item in tips["what"]:
                html += f"<li>{item}</li>"
            for item in tips["where"]:
                html += f"<li><em>{item}</em></li>"
            html += "</ul>"
        html += "</details>"

        html += "<details><summary>🔍 Full Alert Details</summary>"
        for key, value in flat.items():
            explanation = get_field_explanation(key)
            html += f"<div class='field'><span class='key'>{key}:</span>&nbsp;&nbsp;{value}<br><em>{explanation}</em></div><br>"
        html += "</details>"

        html += "<details><summary>🎯 Recommended Actions</summary><ul>"
        for line in recommend_response(alert, return_text=True).splitlines():
            html += f"<li>{line}</li>"
        html += "</ul></details>"

        html += "</div>"

    html += HTML_FOOT

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
