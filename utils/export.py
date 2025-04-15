import os
import hashlib
import json
from utils.enrich import enrich_ip
from triage.recommend import recommend_response


try:
    from utils.enrich import enrich_virustotal
except ImportError:
    enrich_virustotal = None


def generate_html_report(alerts, output_path):
    html = """
    <html>
    <head>
        <title>SOCscribe Alert Report</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .panel { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px #ccc; margin-bottom: 20px; }
            h2 { color: #003366; }
            h3 { color: #006699; }
            code { background: #eee; padding: 2px 4px; border-radius: 4px; }
            em { color: #666; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <h1>SOCscribe Alerts Report</h1>
    """

    # Load config once
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    try:
        with open(config_path, "r") as c:
            config = json.load(c)
            abuse_key = config.get("abuseipdb_key")
            vt_key = config.get("virustotal_key")
    except:
        abuse_key = None
        vt_key = None

    for alert in alerts:
        rule = alert.get("rule", {})
        src_ip = alert.get("srcip", "N/A")
        timestamp = alert.get("timestamp", "N/A")
        host = alert.get("agent", {}).get("name", "unknown")
        full_log = alert.get("full_log", "")
        rule_id = str(rule.get("id"))
        description = rule.get("description", "No description")

        # Enrichments
        ip_data = enrich_ip(src_ip, abuse_key)
        vt_data = {}
        if vt_key and full_log and enrich_virustotal:
            hash_val = hashlib.sha256(full_log.encode()).hexdigest()
            vt_data = enrich_virustotal(hash_val, vt_key)

        # Start panel for alert
        html += f"""
        <div class="panel">
            <h2>🚨 Alert ID: {alert.get('id')}</h2>
            <p><strong>Timestamp:</strong> {timestamp}</p>
            <p><strong>Host:</strong> {host}</p>
            <p><strong>Source IP:</strong> {src_ip}</p>
            <p><strong>Description:</strong> {description}</p>
        """

        mitre = rule.get("mitre", {})
        if mitre:
            html += f"""
            <p><strong>MITRE Tactic:</strong> {mitre.get("tactic", "Unknown")}<br/>
            <strong>Technique:</strong> {mitre.get("technique", "Unknown")} ({mitre.get("id", "-")})</p>
            """

        if ip_data.get("geo"):
            geo = ip_data["geo"]
            html += f"<p><strong>Geo Info:</strong> {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}<br/>"
            html += "<em>(The suspected origin of the IP address involved.)</em></p>"

        if ip_data.get("abuse"):
            abuse = ip_data["abuse"]
            html += f"<p><strong>AbuseIPDB:</strong> {abuse.get('abuseConfidenceScore', 0)}/100 | Reports: {abuse.get('totalReports', 0)}<br/>"
            html += "<em>(Community-submitted threat score of this IP.)</em></p>"

        if vt_data and "positives" in vt_data:
            html += f"<p><strong>VirusTotal:</strong> {vt_data['positives']} detections | <a href='{vt_data['link']}'>View Report</a><br/>"
            html += "<em>(Number of AV engines that flagged this file.)</em></p>"

        html += "<h3>🎯 Recommended Actions</h3><ul>"
        actions = recommend_response(alert, return_text=True).splitlines()
        for a in actions:
            html += f"<li>{a}</li>"
        html += "</ul>"

        # Role guidance
        html += "<h3>🧑‍💼 Who Should Investigate This?</h3><p>"
        if "brute force" in description.lower():
            html += "This can be handled by a <strong>Tier 1 SOC Analyst</strong>.<br/><em>(Likely login abuse or scanning.)</em>"
        elif mitre.get("tactic", "").lower() in ["persistence", "privilege escalation"]:
            html += "Escalate to <strong>Threat Hunter</strong> or <strong>Incident Responder</strong>.<br/><em>(Possible lateral movement.)</em>"
        elif mitre.get("technique", "").lower().startswith("malicious file"):
            html += "A <strong>Malware Analyst</strong> should inspect this file.<br/><em>(Suspicious payload involved.)</em>"
        elif "exfiltration" in mitre.get("tactic", "").lower():
            html += "Escalate to <strong>SOC Lead</strong>.<br/><em>(Potential data breach.)</em>"
        else:
            html += "Start with a <strong>Tier 1 SOC Analyst</strong>.<br/><em>Escalate if needed.</em>"
        html += "</p></div>"

    html += "</body></html>"

    with open(output_path, "w") as f:
        f.write(html)
