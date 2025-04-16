import os
import signal
import time
import json
from datetime import datetime
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

                                timestamp = alert.get("timestamp", "").replace("T", " @ ").split(".")[0]
                                summary = alert.get("rule", {}).get("description", "[No Description]")
                                level = int(alert.get("rule", {}).get("level", 0))

                                # Severity tag
                                if level >= 10:
                                    tag = "🔴 High"
                                elif level >= 6:
                                    tag = "🟠 Medium"
                                else:
                                    tag = "🟢 Low"

                                console.print(f"[cyan]{timestamp}[/cyan]  {summary} [{tag} Severity]")
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

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = os.path.join(os.getcwd(), "exports")
    os.makedirs(export_dir, exist_ok=True)
    output_path = os.path.join(export_dir, f"report_{timestamp}.html")

    export_alerts(alerts, output_path)
    console.print(f"\n[bold green]✅ Export complete! Saved to:[/bold green] [cyan]{output_path}[/cyan]")

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
