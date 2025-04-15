from rich.console import Console
from rich.panel import Panel
import json, os

console = Console()

def explain_alert(alert):
    rule = alert.get("rule", {})
    src_ip = alert.get("srcip", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    host = alert.get("agent", {}).get("name", "unknown")
    rule_id = str(rule.get("id"))

    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks.json')
    mitre_output = ""
    try:
        with open(data_path, "r") as f:
            playbooks = json.load(f)

        if rule_id in playbooks:
            mitre = playbooks[rule_id]
            mitre_output = f"[bold white]🧠 MITRE Tactic:[/] {mitre['tactic']}\n[bold white]🛠 Technique:[/] {mitre['technique']} ({mitre['technique_id']})"
        else:
            mitre_output = "[bold white]🧠 MITRE Tactic:[/] Unknown\n[bold white]🛠 Technique:[/] Unknown"
    except Exception as e:
        mitre_output = f"[red]❌ Error loading MITRE mapping: {e}"

    # Display all in a formatted panel
    panel_text = f"""
[bold red]🚨 Alert ID:[/] {alert.get('id')}
[bold yellow]🕒 Timestamp:[/] {timestamp}
[bold cyan]💻 Host:[/] {host}
[bold magenta]🌐 Source IP:[/] {src_ip}
[bold green]📜 Description:[/] {rule.get('description')}

{mitre_output}
    """
    console.print(Panel(panel_text.strip(), title="[bold blue]🔍 Alert Summary", expand=False))
