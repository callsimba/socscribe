from rich.console import Console
from rich.text import Text
import json, os

console = Console()

def explain_alert(alert):
    rule = alert.get("rule", {})
    src_ip = alert.get("srcip", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    host = alert.get("agent", {}).get("name", "unknown")
    rule_id = str(rule.get("id"))

    console.print(f"[bold red]🚨 Alert ID:[/] {alert.get('id')}")
    console.print(f"[bold yellow]🕒 Timestamp:[/] {timestamp}")
    console.print(f"[bold cyan]💻 Host:[/] {host}")
    console.print(f"[bold magenta]🌐 Source IP:[/] {src_ip}")
    console.print(f"[bold green]📜 Description:[/] {rule.get('description')}")

    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks.json')
    try:
        with open(data_path, "r") as f:
            playbooks = json.load(f)

        if rule_id in playbooks:
            mitre = playbooks[rule_id]
            console.print(f"[bold white]🧠 MITRE Tactic:[/] {mitre['tactic']}")
            console.print(f"[bold white]🛠 Technique:[/] {mitre['technique']} ({mitre['technique_id']})")
        else:
            console.print("[bold white]🧠 MITRE Tactic:[/] Unknown")
            console.print("[bold white]🛠 Technique:[/] Unknown")
    except Exception as e:
        console.print(f"[red]❌ Error loading MITRE mapping: {e}")
