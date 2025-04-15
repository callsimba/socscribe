from rich.console import Console
from rich.text import Text
from utils.eventid_map import get_event_description

console = Console()

def explain_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
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
    text.append(f"🛠 Technique: {mitre['technique']} ({mitre['id']})\n")

    # Optional: Geo + ISP info from enrichment
    if alert.get("geo_info"):
        geo = alert["geo_info"]
        text.append(f"🌍 Geo Info: {geo['city']}, {geo['region']}, {geo['country']} | ISP: {geo['isp']}\n")

    console.print(text, style="bold cyan")

    # Field-aware explanations
    event_data = alert.get("data", {}).get("win", {}).get("eventdata", {})
    system_data = alert.get("data", {}).get("win", {}).get("system", {})

    if system_data.get("eventID"):
        eid = str(system_data["eventID"])
        event_desc = get_event_description(eid)
        console.print(f"📘 Sysmon Event ID {eid}: {event_desc}", style="bold green")

    if event_data.get("image"):
        console.print(f"\n⚙️ Process Executed: {event_data['image']}")
        console.print("(This is the executable that triggered the event — e.g., powershell.exe)", style="dim")

    if event_data.get("commandLine"):
        console.print(f"\n📝 Command Line: {event_data['commandLine']}")
        console.print("(This shows how the process was executed — watch for obfuscation.)", style="dim")

    if event_data.get("targetFilename"):
        console.print(f"\n📁 Target File Created: {event_data['targetFilename']}")
        console.print("(This file was written to disk — may indicate payload drop.)", style="dim")

    if event_data.get("user"):
        console.print(f"\n👤 Executed By User: {event_data['user']}")
        console.print("(The user account that ran the process or triggered the event.)", style="dim")

    if event_data.get("parentImage"):
        console.print(f"\n🧬 Parent Process: {event_data['parentImage']}")
        console.print("(This is the process that launched the one being logged — useful for tracing chains.)", style="dim")

    if event_data.get("parentCommandLine"):
        console.print(f"\n🔗 Parent Command Line: {event_data['parentCommandLine']}")
        console.print("(This shows how the parent process was invoked.)", style="dim")
