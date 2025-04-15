import os
import hashlib
import json
from utils.enrich import enrich_ip
try:
    from utils.enrich import enrich_virustotal
except ImportError:
    enrich_virustotal = None

def generate_html_report(alert, output_path):
    rule = alert.get("rule", {})
    src_ip = alert.get("srcip", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    host = alert.get("agent", {}).get("name", "unknown")
    full_log = alert.get("full_log", "")
    rule_id = str(rule.get("id"))

    # Load config
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    try:
        with open(config_path, "r") as c:
            config = json.load(c)
            abuse_key = config.get("abuseipdb_key")
            vt_key = config.get("virustotal_key")
    except:
        abuse_key = None
        vt_key = None

    # Load playbooks
    mitre = {}
    playbook_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks.json')
    try:
        with open(playbook_path, "r") as f:
            playbooks = json.load(f)
            mitre = playbooks.get(rule_id, {})
    except:
        pass

    # Enrichments
    ip_data = enrich_ip(src_ip, abuse_key)
    vt_data = {}
    if vt_key and full_log and enrich_virustotal:
        hash_val = hashlib.sha256(full_log.encode()).hexdigest()
        vt_data = enrich_virustotal(hash_val, vt_key)

    # HTML content
    html = f"""
<html>
<head>
    <title>SOCscribe Alert Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
        .panel {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px #ccc; }}
        h2 {{ color: #003366; }}
        h3 {{ color: #006699; }}
        code {{ background: #eee; padding: 2px 4px; border-radius: 4px; }}
        em {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="panel">
        <h2>🔍 Alert Summary</h2>
        <p><strong>Alert ID:</strong> {alert.get('id')}<br/>
        <em>(This is the unique identifier of the alert event.)</em></p>

        <p><strong>Timestamp:</strong> {timestamp}<br/>
        <em>(The exact time the alert was triggered.)</em></p>

        <p><strong>Host:</strong> {host}<br/>
        <em>(The system or endpoint where the alert was detected.)</em></p>

        <p><strong>Source IP:</strong> {src_ip}<br/>
        <em>(The IP address where the activity came from — could be an attacker.)</em></p>

        <p><strong>Description:</strong> {rule.get('description')}<br/>
        <em>(A summary of what triggered this alert.)</em></p>

        <p><strong>MITRE Tactic:</strong> {mitre.get('tactic', 'Unknown')}<br/>
        <em>(The adversary’s goal — what they’re trying to do.)</em></p>

        <p><strong>Technique:</strong> {mitre.get('technique', 'Unknown')} ({mitre.get('technique_id', '-')})<br/>
        <em>(How the attacker tried to achieve the tactic above.)</em></p>
    """


    if ip_data.get("geo"):
        geo = ip_data["geo"]
        html += f"<p><strong>Geo Info:</strong> {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}</p>"

    if ip_data.get("abuse"):
        abuse = ip_data["abuse"]
        html += f"<p><strong>AbuseIPDB:</strong> {abuse.get('abuseConfidenceScore', 0)}/100 | Reports: {abuse.get('totalReports', 0)}</p>"

    if vt_data and "positives" in vt_data:
        html += f"<p><strong>VirusTotal:</strong> {vt_data['positives']} detections | <a href='{vt_data['link']}'>View Report</a></p>"

    html += "<h3>🎯 Recommended Actions</h3><ul>"
        # Analyst Role Recommendation
    html += "</ul><h3>🧑‍💼 Who Should Investigate This?</h3><p>"

    # Heuristic based on technique or description
    if "brute force" in rule.get("description", "").lower():
        html += "This can be handled by a <strong>Tier 1 SOC Analyst</strong>.<br/><em>(It's likely part of external scanning or credential stuffing attempts.)</em>"
    elif mitre.get("tactic", "").lower() in ["persistence", "privilege escalation"]:
        html += "This should be escalated to a <strong>Threat Hunter</strong> or <strong>Incident Responder</strong>.<br/><em>(It may indicate attempts to gain deeper access.)</em>"
    elif mitre.get("technique", "").lower().startswith("malicious file"):
        html += "A <strong>Malware Analyst</strong> should inspect the sample or logs.<br/><em>(This might involve malicious payloads.)</em>"
    elif "exfiltration" in mitre.get("tactic", "").lower():
        html += "Escalate immediately to a <strong>SOC Lead</strong>.<br/><em>(This may involve data theft.)</em>"
    else:
        html += "Start with a <strong>Tier 1 SOC Analyst</strong>. If suspicious patterns persist, escalate to <strong>Threat Hunter</strong>."

    html += "</p>"

    actions = mitre.get("actions", [])
    for a in actions:
        html += f"<li>{a}</li>"
    html += "</ul></div></body></html>"

    with open(output_path, "w") as f:
        f.write(html)
