import os
import time
import json
from datetime import datetime
from rich.console import Console
from utils.export import export_alerts
from utils.mitre_index import get_investigation_tips
from utils.flatten import flatten_dict
from utils.severity import enrich_alert  # 🔄 Moved here

console = Console()
alerts = []
ALERT_LOG_PATH = os.path.expanduser("~/wazuh-logs/alerts.json")

def calculate_severity(alert):
    rule = alert.get("rule", {})
    tactic = rule.get("mitre", {}).get("tactic", "")
    if isinstance(tactic, list):
        tactic = tactic[0] if tactic else ""
    tactic = tactic.title()
    flat = flatten_dict(alert) if 'flatten_dict' in globals() else alert
    cmd = flat.get("data.win.eventdata.commandLine", "").lower()
    desc = rule.get("description", "").lower()
    mitre_id = str(rule.get("mitre", {}).get("id", "")).lower()
    fired = int(rule.get("firedtimes", 0))
    parent = flat.get("data.win.eventdata.parentImage", "").lower()
    image = flat.get("data.win.eventdata.image", "").lower()
    logon_type = flat.get("data.win.eventdata.logonType", "")
    high_tactics = ["t1059", "t1105", "t1547", "t1021", "t1218", "t1566", "t1055", "t1112"]
    if any(mitre_id.startswith(tid) for tid in high_tactics):
        return 10
    if any(tool in image for tool in ["rundll32", "regsvr32", "mshta", "wmic", "powershell", "cmd.exe"]):
        return 9
    if logon_type in ["3", "10"]:
        return 8
    if fired >= 5:
        return 7
    if any(x in cmd for x in ["invoke-", "downloadfile", "bypass", "base64"]):
        return 7
    if any(x in parent for x in ["powershell", "wscript", "cscript"]):
        return 6
    return int(rule.get("level", 0))

def tail_alerts():
    seen = set()
    console.print(f"📡 Listening for new alerts in: [bold yellow]{ALERT_LOG_PATH}[/bold yellow]")
    try:
        while True:
            try:
                with open(ALERT_LOG_PATH, 'r') as f:
                    for line in f:
                        try:
                            alert = json.loads(line)
                            alert_id = alert.get("id")
                            if alert_id and alert_id not in seen:
                                seen.add(alert_id)
                                alert = enrich_alert(alert, calculate_severity)
                                timestamp = alert.get("timestamp", "").replace("T", " @ ").split(".")[0]
                                summary = alert.get("rule", {}).get("description", "[No Description]")
                                tag = alert["_severity_label"]
                                icon = "🔴" if tag == "High" else "🟠" if tag == "Medium" else "🟢"
                                console.print(f"[cyan]{timestamp}[/cyan]  {summary} [{icon} {tag}]")
                                alerts.append(alert)
                        except json.JSONDecodeError:
                            continue
            except FileNotFoundError:
                console.print(f"[red]❌ File not found: {ALERT_LOG_PATH}[/red]")
                break
            except PermissionError:
                console.print(f"[red]❌ Permission denied: {ALERT_LOG_PATH}[/red]")
                break
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⏹️ Detected Ctrl+C — exporting alerts...[/bold yellow]")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_dir = os.path.join(os.getcwd(), "exports")
        os.makedirs(export_dir, exist_ok=True)
        output_path = os.path.join(export_dir, f"report_{timestamp}.html")
        export_alerts(alerts, output_path)
        console.print(f"\n[bold green]✅ Export complete! Saved to:[/bold green] [cyan]{output_path}[/cyan]")
        exit()

def load_file_and_export():
    with open(ALERT_LOG_PATH, 'r') as f:
        for line in f:
            try:
                alert = json.loads(line)
                alert = enrich_alert(alert, calculate_severity)
                alerts.append(alert)
            except json.JSONDecodeError:
                continue
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = os.path.join(os.getcwd(), "exports")
    os.makedirs(export_dir, exist_ok=True)
    output_path = os.path.join(export_dir, f"report_{timestamp}.html")
    export_alerts(alerts, output_path)
    console.print(f"\n[bold green]✅ Export complete! Saved to:[/bold green] [cyan]{output_path}[/cyan]")

def main():
    console.print("""
[bold magenta]─────────────────────────────────────────── SOCscribe Setup Wizard ───────────────────────────────────────────[/bold magenta]
Choose mode:
[1] Watch
[2] File
""")
    mode = input("Choose mode [1/2] (2): ").strip()
    if mode == "1":
        tail_alerts()
    else:
        load_file_and_export()

if __name__ == "__main__":
    main()
