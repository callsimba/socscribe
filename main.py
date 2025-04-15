import os
import signal
import time
import json
from rich.console import Console
from utils.export import export_alerts



console = Console()
alerts = []

# Path to Wazuh alert file
ALERT_LOG_PATH = os.path.expanduser("~/wazuh-logs/alerts.json")

# ───────────────────────────────────────────────────────────────
# Watch mode: print only summary lines, export on Ctrl+C
# ───────────────────────────────────────────────────────────────

def tail_alerts():
    seen = set()
    try:
        while True:
            with open(ALERT_LOG_PATH, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line)
                        alert_id = alert.get("id")
                        if alert_id and alert_id not in seen:
                            seen.add(alert_id)
                            timestamp = alert.get("timestamp", "").replace("T", " @ ").split(".")[0]
                            summary = alert.get("rule", {}).get("description", "[No Description]")
                            console.print(f"[cyan]{timestamp}[/cyan]  {summary}")
                            alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
            time.sleep(2)
    except KeyboardInterrupt:
        export_alerts(alerts)
        console.print("\n[bold green]✅ Export complete. Exiting.[/bold green]")
        exit()

# ───────────────────────────────────────────────────────────────
# File mode: load all alerts and export immediately
# ───────────────────────────────────────────────────────────────

def load_file_and_export():
    with open(ALERT_LOG_PATH, 'r') as f:
        for line in f:
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError:
                continue
    export_alerts(alerts)

# ───────────────────────────────────────────────────────────────
# Entry point
# ───────────────────────────────────────────────────────────────

def main():
    console.print("""
[bold magenta]─────────────────────────────────────────── SOCscribe Setup Wizard ───────────────────────────────────────────[/bold magenta]
Choose mode:
[1] Watch
[2] File
""")
    mode = input("Choose mode [1/2] (2): ").strip()
    if mode == "1":
        console.print(f"📡 Listening for new alerts in: [bold yellow]{ALERT_LOG_PATH}[/bold yellow]")
        tail_alerts()
    else:
        load_file_and_export()

if __name__ == "__main__":
    main()
