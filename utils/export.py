import json
from utils.flatten import flatten_dict
from utils.mitre_index import get_investigation_tips, MITRE_SEVERITY_MAP

def calculate_severity(alert):
    try:
        with open("severity_rules.json", "r") as f:
            config = json.load(f)
    except:
        config = {"mitre": {}, "keywords": {}}

    rule = alert.get("rule", {})
    tactic = rule.get("mitre", {}).get("tactic", "")
    if isinstance(tactic, list):
        tactic = tactic[0] if tactic else ""
    tactic = tactic.title()

    flat = flatten_dict(alert)
    cmd = flat.get("data.win.eventdata.commandLine", "").lower()
    desc = rule.get("description", "").lower()
    mitre_id = str(rule.get("mitre", {}).get("id", "")).upper()

    for keyword, level in config.get("keywords", {}).items():
        if keyword in cmd or keyword in desc:
            alert["_severity_reason"] = f"Triggered by: '{keyword}' (keyword)"
            return {"Low": 3, "Medium": 6, "High": 10}.get(level, 3)

    if mitre_id in config.get("mitre", {}):
        level_str = config["mitre"][mitre_id]
        alert["_severity_reason"] = f"Overridden by: {mitre_id} (MITRE ID)"
        return {"Low": 3, "Medium": 6, "High": 10}.get(level_str, 3)

    severity = MITRE_SEVERITY_MAP.get(tactic, "Low")
    alert["_severity_reason"] = f"Inferred from: {tactic} (MITRE tactic)"
    return {"Low": 3, "Medium": 6, "High": 10}.get(severity, 3)

# Include this HTML snippet in the export function for filtering logic
html_script = """
<script>
function resetFilters() {
  document.querySelectorAll('.panel.alert').forEach(el => el.classList.remove('hidden'));
  document.getElementById('startDate').value = "";
  document.getElementById('endDate').value = "";
  document.getElementById('searchBox').value = "";
  document.getElementById('keywordBox').value = "";
  document.getElementById('tacticBox').value = "";
  document.getElementById('severityFilter').value = "";
}

function filterByDate() {
  const start = new Date(document.getElementById('startDate').value);
  const end = new Date(document.getElementById('endDate').value);
  document.querySelectorAll('.panel.alert').forEach(el => {
    const ts = new Date(el.dataset.timestamp);
    const show = (!isNaN(start) ? ts >= start : true) && (!isNaN(end) ? ts <= end : true);
    el.classList.toggle('hidden', !show);
  });
}

function searchText() {
  const q = document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('.panel.alert').forEach(el => {
    el.classList.toggle('hidden', !el.textContent.toLowerCase().includes(q));
  });
}

function filterByKeyword() {
  const q = document.getElementById('keywordBox').value.toLowerCase();
  document.querySelectorAll('.panel.alert').forEach(el => {
    el.classList.toggle('hidden', !el.textContent.toLowerCase().includes(q));
  });
}
</script>
"""
