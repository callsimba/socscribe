def explain_alert(alert):
    rule = alert.get("rule", {})
    src_ip = alert.get("srcip", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    host = alert.get("agent", {}).get("name", "unknown")

    print(f"🚨 Alert ID: {alert.get('id')}")
    print(f"🕒 Timestamp: {timestamp}")
    print(f"💻 Host: {host}")
    print(f"🌐 Source IP: {src_ip}")
    print(f"📜 Description: {rule.get('description')}")
    print(f"🧠 MITRE Tactic: {', '.join(rule.get('mitre', {}).get('tactic', []))}")
    print(f"🛠 Technique: {', '.join(rule.get('mitre', {}).get('technique', []))}")
