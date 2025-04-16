import os
import hashlib
import json
from utils.enrich import enrich_ip
from triage.recommend import recommend_response
from triage.field_explanations import get_field_explanation

try:
    from utils.enrich import enrich_virustotal
except ImportError:
    enrich_virustotal = None


def generate_field_blocks(alert):
    """Generate HTML field blocks with explanations for top-level and nested fields"""
    blocks = ""
    flat = flatten_json(alert)

    for key, value in flat.items():
        explanation = get_field_explanation(key)
        blocks += f"""
        <p><strong>{key}:</strong> {value}
        <details><summary>What does this mean?</summary>
        <em>{explanation}</em>
        </details></p>
        """
    return blocks


def flatten_json(y, parent_key='', sep='.'):
    """Flattens nested JSON into dot notation keys"""
    items = []
    for k, v in y.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_json(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def export_alerts(alerts, output_path):
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
            details { margin-top: 5px; font-size: 0.9em; }
            summary { cursor: pointer; color: #444; }
        </style>
    </head>
    <body>
        <h1>SOCscribe Alerts Report</h1>
    """

    for alert in alerts:
        rule = alert.get("rule", {})
        description = rule.get("description", "No description")
        alert_id = alert.get("id", "Unknown")

        html += f"""
        <div class="panel">
            <h2>🚨 Alert ID: {alert_id}</h2>
            <h3>{description}</h3>
        """

        html += generate_field_blocks(alert)

        html += "<h3>🎯 Recommended Actions</h3><ul>"
        actions = recommend_response(alert, return_text=True).splitlines()
        for a in actions:
            html += f"<li>{a}</li>"
        html += "</ul></div>"

    html += "</body></html>"

    with open(output_path, "w") as f:
        f.write(html)
