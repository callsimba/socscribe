from rich.console import Console
from rich.panel import Panel
from utils.enrich import enrich_ip
import json
import os
import hashlib

# Optional VT import
try:
    from utils.enrich import enrich_virustotal
except ImportError:
    enrich_virustotal = None

console = Console()

def explain_alert(alert):
    rule = alert.get("rule", {})
    src_ip = alert.get("srcip", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    host = alert.get("agent", {}).get("name", "unknown")
    rule_id = str(rule.get("id"))
    full_log = alert.get("full_log", "")

    # Load config
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    try:
        with open(config_path, "r") as c:
            config = json.load(c)
            abuse_key = config.get("abuseipdb_key")
            vt_key = config.get("virustotal_key")
    except:
        abuse_key = None
        vt_key = None

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

    # Enrich IP
    ip_data = enrich_ip(src_ip, abuseipdb_key=abuse_key)

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

    # Optional VirusTotal Lookup
    vt_output = ""
    if vt_key and full_log and enrich_virustotal:
        file_hash = hashlib.sha256(full_log.encode()).hexdigest()
        vt_data = enrich_virustotal(file_hash, vt_key)
        if "positives" in vt_data:
            vt_output = f"[bold magenta]🧪 VirusTotal:[/] {vt_data['positives']} detections | [link={vt_data['link']}]View Report[/link]"
        elif "error" in vt_data:
            vt_output = f"[yellow]⚠️ VT Error: {vt_data['error']}[/]"

    # Render Output
    panel_text = f"""
[bold red]🚨 Alert ID:[/] {alert.get('id')}
[bold yellow]🕒 Timestamp:[/] {timestamp}
[bold cyan]💻 Host:[/] {host}
[bold magenta]🌐 Source IP:[/] {src_ip}
[bold green]📜 Description:[/] {rule.get('description')}

{mitre_output}
{geo_output}
{abuse_output}
{vt_output}
    """

    console.print(Panel(panel_text.strip(), title="[bold blue]🔍 Alert Summary", expand=False))
