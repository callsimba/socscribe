#!/usr/bin/env python3
import os
import sys
import time
import json
import signal
import threading
import termios, tty
from datetime import datetime
from queue import Queue, Empty
from rich.console import Console

from utils.export   import export_alerts
from utils.flatten  import flatten_dict
from utils.severity import enrich_alert

console        = Console()
ALERT_LOG_PATH = os.path.expanduser("~/wazuh-logs/alerts.json")
alerts         = []
key_queue      = Queue()
CTRL_Q         = "\x11"

def calculate_severity(alert):
    rule       = alert.get("rule", {})
    flat       = flatten_dict(alert)
    mitre_id   = str(rule.get("mitre", {}).get("id", "")).lower()
    fired      = int(rule.get("firedtimes", 0))
    image      = flat.get("data.win.eventdata.image",       "").lower()
    parent     = flat.get("data.win.eventdata.parentImage", "").lower()
    cmd        = flat.get("data.win.eventdata.commandLine", "").lower()
    logon_type = flat.get("data.win.eventdata.logonType", "")
    high_ttps  = ["t1059","t1105","t1547","t1021","t1218","t1566","t1055","t1112"]
    if any(mitre_id.startswith(t) for t in high_ttps):
        return 10
    if any(tool in image for tool in ["rundll32","regsvr32","mshta","wmic","powershell","cmd.exe"]):
        return 9
    if logon_type in ["3","10"]:
        return 8
    if fired >= 5:
        return 7
    if any(x in cmd for x in ["invoke-","downloadfile","bypass","base64"]):
        return 7
    if any(x in parent for x in ["powershell","wscript","cscript"]):
        return 6
    return int(rule.get("level", 0))

ctrl_c_count = 0
def sigint_handler(signum, frame):
    global ctrl_c_count
    ctrl_c_count += 1
    if ctrl_c_count == 1:
        console.print("\n[bold yellow]↩ Returning to main menu… (press Ctrl+C again to quit)[/bold yellow]")
        raise KeyboardInterrupt
    else:
        console.print("\n[bold red]👋 SOCscribe closed. Stay safe![/bold red]")
        sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

def key_listener():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    try:
        while True:
            ch = sys.stdin.read(1)
            key_queue.put(ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
threading.Thread(target=key_listener, daemon=True).start()

def tail_alerts():
    global ctrl_c_count
    ctrl_c_count = 0
    seen               = set()
    idle_prompt_shown  = False
    last_activity      = time.time()
    idle_seconds       = 10
    console.print(f"📡 Listening for new alerts in: [bold yellow]{ALERT_LOG_PATH}[/bold yellow]")
    try:
        while True:
            new_data = False
            try:
                with open(ALERT_LOG_PATH, "r") as f:
                    for line in f:
                        try:
                            alert = json.loads(line)
                            aid   = alert.get("id")
                            if aid and aid not in seen:
                                seen.add(aid)
                                alert = enrich_alert(alert, calculate_severity)
                                ts    = alert.get("timestamp","").replace("T"," @ ").split(".")[0]
                                msg   = alert.get("rule",{}).get("description","[No Description]")
                                sev   = alert["_severity_label"]
                                icon  = "🔴" if sev=="High" else "🟠" if sev=="Medium" else "🟢"
                                console.print(f"[cyan]{ts}[/cyan] {msg} [{icon} {sev}]")
                                alerts.append(alert)
                                new_data = True
                        except json.JSONDecodeError:
                            continue
            except FileNotFoundError:
                console.print(f"[red]❌ File not found: {ALERT_LOG_PATH}[/red]")
                break
            except PermissionError:
                console.print(f"[red]❌ Permission denied: {ALERT_LOG_PATH}[/red]")
                break
            if new_data:
                last_activity      = time.time()
                idle_prompt_shown  = False
            try:
                ch = key_queue.get_nowait()
                if ch == CTRL_Q:
                    export_current()
                    last_activity     = time.time()
                    idle_prompt_shown = False
            except Empty:
                pass
            if not idle_prompt_shown and time.time() - last_activity > idle_seconds:
                console.print("[dim]⏳ Press Ctrl+Q at any time to export a snapshot report.[/dim]")
                idle_prompt_shown = True
            time.sleep(1)
    except KeyboardInterrupt:
        return

def export_current():
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir  = os.path.join(os.getcwd(), "exports")
    os.makedirs(export_dir, exist_ok=True)
    output_path = os.path.join(export_dir, f"report_{timestamp}.html")
    export_alerts(alerts, output_path)
    console.print(f"[bold green]✅ Report saved to:[/bold green] [cyan]{output_path}[/cyan]")

def load_file_and_export():
    with open(ALERT_LOG_PATH, "r") as f:
        for line in f:
            try:
                alert = json.loads(line)
                alerts.append(enrich_alert(alert, calculate_severity))
            except json.JSONDecodeError:
                continue
    export_current()

def main():
    while True:
        console.print("""
[bold magenta]──────────────────────────────── SOCscribe ────────────────────────────────[/bold magenta]
[1] Watch live alerts
[2] Export entire alert log to HTML
[Ctrl+C]  Exit
""")
        choice = input("Choose option [1/2] (1): ").strip() or "1"
        if choice == "1":
            tail_alerts()
        elif choice == "2":
            load_file_and_export()
        else:
            console.print("[red]Invalid option.[/red]")

if __name__ == "__main__":
    main()
