from rich.console import Console
from rich.panel import Panel
from utils.enrich import enrich_ip
import json
import os

console = Console()

def explain_alert(alert):
    rule = alert.get("rule", {})
    src_ip = alert.get("srcip", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    host = alert.get("agent", {}).get("name", "unknown")
    rule_id = str(rule.get("id"))

    # Load playbook (MITRE mapping)
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

    # Enrich the IP
    ip_data = enrich_ip(src_ip)

    geo_output = ""
    if "geo" in ip_data:
        geo = ip_data["geo"]
        if "country" in geo:
            geo_output = f"[bold blue]🌍 Geo Info:[/] {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}"
        elif "error" in geo:
            geo_output = f"[yellow]⚠️ {geo['error']}[/]"

    abuse_output = ""
    if "abuse" in ip_data:
        abuse = ip_data["abuse"]
        if "abuseConfidenceScore" in abuse:
            score = abuse["abuseConfidenceScore"]
            abuse_output = f"[bold red]🚩 Abuse Score:[/] {score}/100 | Reports: {abuse['totalReports']}"
        elif "error" in abuse:
            abuse_output = f"[yellow]⚠️ {abuse['error']}[/]"

    # Render panel
    panel_text = f"""
[bold red]🚨 Alert ID:[/] {alert.get('id')}
[bold yellow]🕒 Timestamp:[/] {timestamp}
[bold cyan]💻 Host:[/] {host}
[bold magenta]🌐 Source IP:[/] {src_ip}
[bold green]📜 Description:[/] {rule.get('description')}

{mitre_output}
{geo_output}
{abuse_output}
    """

    console.print(Panel(panel_text.strip(), title="[bold blue]🔍 Alert Summary", expand=False))
