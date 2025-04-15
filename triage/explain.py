import os
import json

def explain_alert(alert):
    rule = alert.get("rule", {})
    src_ip = alert.get("srcip", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    host = alert.get("agent", {}).get("name", "unknown")
    rule_id = str(rule.get("id"))

    print(f"🚨 Alert ID: {alert.get('id')}")
    print(f"🕒 Timestamp: {timestamp}")
    print(f"💻 Host: {host}")
    print(f"🌐 Source IP: {src_ip}")
    print(f"📜 Description: {rule.get('description')}")

    # Load MITRE data from playbooks.json
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks.json')

    try:
        with open(data_path, "r") as f:
            playbooks = json.load(f)

        if rule_id in playbooks:
            mitre = playbooks[rule_id]
            print(f"🧠 MITRE Tactic: {mitre['tactic']}")
            print(f"🛠 Technique: {mitre['technique']} ({mitre['technique_id']})")
        else:
            print("🧠 MITRE Tactic: Unknown")
            print("🛠 Technique: Unknown")
    except Exception as e:
        print(f"❌ Error loading MITRE mapping: {e}")
