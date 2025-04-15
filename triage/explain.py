from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from utils.eventid_map import get_event_description

console = Console()

def explain_alert(alert, return_text=False):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = {
        "tactic": rule.get("mitre", {}).get("tactic", "Unknown"),
        "technique": rule.get("mitre", {}).get("technique", "Unknown"),
        "id": rule.get("mitre", {}).get("id", "-")
    }

    geo = alert.get("geo_info")
    event_data = alert.get("data", {}).get("win", {}).get("eventdata", {})
    system_data = alert.get("data", {}).get("win", {}).get("system", {})

    text = Text()
    text.append(f"🚨 Alert ID: {alert.get('id')}\n")
    text.append(f"🕒 Timestamp: {alert.get('timestamp')}\n")
    text.append(f"💻 Host: {agent.get('name', 'unknown')}\n")
    text.append(f"🌐 Source IP: {alert.get('srcip', 'N/A')}\n")
    text.append(f"📜 Description: {rule.get('description', 'No description')}\n\n")
    text.append(f"🧠 MITRE Tactic: {mitre['tactic']}\n")
    text.append(f"🛠 Technique: {mitre['technique']} ({mitre['id']})\n\n")

    if geo:
        text.append(f"🌍 Geo Info: {geo['city']}, {geo['region']}, {geo['country']} | ISP: {geo['isp']}\n")

    if system_data.get("eventID"):
        eid = str(system_data["eventID"])
        event_desc = get_event_description(eid)
        text.append(f"\n📘 Sysmon Event ID {eid}: {event_desc}\n")

    if event_data.get("image"):
        text.append(f"\n⚙️ Process Executed: {event_data['image']}\n")
        text.append("(This is the executable that triggered the event — e.g., powershell.exe)\n")

    if event_data.get("commandLine"):
        text.append(f"\n📝 Command Line: {event_data['commandLine']}\n")
        text.append("(This shows how the process was executed — watch for obfuscation.)\n")

    if event_data.get("targetFilename"):
        text.append(f"\n📁 Target File Created: {event_data['targetFilename']}\n")
        text.append("(This file was written to disk — may indicate payload drop.)\n")

    if event_data.get("user"):
        text.append(f"\n👤 Executed By User: {event_data['user']}\n")
        text.append("(The user account that ran the process or triggered the event.)\n")

    if event_data.get("parentImage"):
        text.append(f"\n🧬 Parent Process: {event_data['parentImage']}\n")
        text.append("(This is the process that launched the one being logged — useful for tracing chains.)\n")

    if event_data.get("parentCommandLine"):
        text.append(f"\n🔗 Parent Command Line: {event_data['parentCommandLine']}\n")
        text.append("(This shows how the parent process was invoked.)\n")

    if return_text:
        return text
    else:
        console.print(Panel(text, title="🎯 Recommended Actions", border_style="green"))
