#!/usr/bin/env python3
import os, sys, time, json, signal, select, threading, termios, tty
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
        raise KeyboardInterrupt
    console.print("\n[bold red]👋 SOCscribe closed.[/bold red]")
    sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

def start_key_listener():
    stop = threading.Event()
    def listen():
        fd   = sys.stdin.fileno()
        old  = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        try:
            while not stop.is_set():
                if sys.stdin in select.select([sys.stdin], [], [], 0.05)[0]:
                    key_queue.put(sys.stdin.read(1))
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    t = threading.Thread(target=listen, daemon=True)
    t.start()
    return t, stop

def tail_alerts():
    global ctrl_c_count
    ctrl_c_count = 0
    listener, stop_flag       = start_key_listener()
    seen, idle_prompt_shown   = set(), False
    last_activity, idle_secs  = time.time(), 10

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
                console.print("[red]❌ File not found:[/] {ALERT_LOG_PATH}")
                break
            except PermissionError:
                console.print("[red]❌ Permission denied:[/] {ALERT_LOG_PATH}")
                break

            if new_data:
                last_activity, idle_prompt_shown = time.time(), False

            try:
                if key_queue.get_nowait() == CTRL_Q:
                    export_current()
                    last_activity, idle_prompt_shown = time.time(), False
            except Empty:
                pass

            if not idle_prompt_shown and time.time() - last_activity > idle_secs:
                console.print("[dim]⏳ Press Ctrl+Q to export a snapshot report.[/dim]")
                idle_prompt_shown = True
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        listener.join(timeout=0.2)

def export_current():
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir  = os.path.join(os.getcwd(), "exports")
    os.makedirs(export_dir, exist_ok=True)
    output_path = os.path.join(export_dir, f"report_{ts}.html")
    export_alerts(alerts, output_path)
    console.print(f"[bold green]✅ Report saved to:[/bold green] [cyan]{output_path}[/cyan]")

BANNER = r"""
 ____   ___   ____               _ _          
/ ___| / _ \ / ___|___  ___ _ __(_) |__   ___ 
\___ \| | | | |   / __|/ __| '__| | '_ \ / _ \
 ___) | |_| | |___\__ \ (__| |  | | |_) |  __/
|____/ \___/ \____|___/\___|_|  |_|_.__/ \___|
                                              
"""

TAGLINE = (
    "[bold cyan]SOCscribe[/bold cyan] – real‑time Wazuh alert watcher & one‑click HTML reporting\n"
    "Developed by [bold]Michael Ebere[/bold] (CallSimba)"
)

def main():
    while True:
        console.print(f"\n{BANNER}{TAGLINE}\n")
        console.print(
            "[bold magenta]───────────────────────────────────────────────[/bold magenta]\n"
            "- PRESS [bold]1[/bold]  to Watch live alerts\n"
            "- Press [bold]Ctrl+Q[/bold] at any time to export a report\n"
            "- Press [bold]Ctrl+C[/bold] once to return here; twice to exit\n"
        )
        choice = input("Press 1 To Start: ").strip() or "1"
        if choice == "1":
            tail_alerts()
        else:
            console.print("[red]Invalid option.[/red]")

if __name__ == "__main__":
    main()
