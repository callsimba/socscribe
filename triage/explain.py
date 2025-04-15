from rich.console import Console
from rich.text import Text
from utils.eventid_map import get_event_description
from utils.sysmon_eventid_map import explain_sysmon_event

console = Console()

def explain_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    mitre = {
        "tactic": rule.get("mitre", {}).get("tactic", "Unknown"),
        "technique": rule.get("mitre", {}).get("technique", "Unknown"),
        "id": rule.get("mitre", {}).get("id", "-")
    }

    # Print summary box
    text = Text()
    text.append(f"🚨 Alert ID: {alert.get('id')}\n")
    text.append(f"🕒 Timestamp: {alert.get('timestamp')}\n")
    text.append(f"💻 Host: {agent.get('name', 'unknown')}\n")
    text.append(f"🌐 Source IP: {alert.get('srcip', 'N/A')}\n")
    text.append(f"📜 Description: {rule.get('description', 'No description')}\n\n")
    text.append(f"🧠 MITRE Tactic: {mitre['tactic']}\n")
    text.append(f"📌 Technique: {mitre['technique']} ({mitre['id']})\n")

    # Explain common deep fields if available
    if "command" in data:
        text.append(f"\n🧾 Command Executed: {data['command']}\n")
    if "commandLine" in data:
        text.append(f"🧾 Command Line: {data['commandLine']}\n")
    if "image" in data:
        text.append(f"🗂️ Image Path: {data['image']}\n")
    if "targetFilename" in data:
        text.append(f"📄 Target File: {data['targetFilename']}\n")
    if "eventID" in data:
        event_id_str = str(data['eventID'])
        sysmon_explanation = explain_sysmon_event(event_id_str)
        if sysmon_explanation:
            text.append(f"\n🔎 Sysmon Event ID {event_id_str}:\n")
            text.append(f"{sysmon_explanation['description']}\n")
            text.append(f"💡 Detection Tip: {sysmon_explanation['detection_tip']}\n")
            text.append(f"🎯 MITRE ID: {sysmon_explanation['mitre_id']} ({sysmon_explanation['mitre_technique']})\n")

    console.print(text)
