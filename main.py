import json
import argparse
import os
import time
from datetime import datetime
from triage.explain import explain_alert
from triage.recommend import recommend_response
from utils.export import generate_html_report
import webbrowser
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()

accumulated_alerts = []


def process_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = {
        "tactic": rule.get("mitre", {}).get("tactic", "Unknown"),
        "technique": rule.get("mitre", {}).get("technique", "Unknown"),
        "id": rule.get("mitre", {}).get("id", "-")
    }

    geo = alert.get("geo_info", {})

    alert_summary = f"""
🚨 Alert ID: {alert.get('id')}
🕒 Timestamp: {alert.get('timestamp')}
💻 Host: {agent.get('name', 'unknown')}
🌐 Source IP: {alert.get('srcip', 'N/A')}
📜 Description: {rule.get('description', 'No description')}

🧠 MITRE Tactic: {mitre['tactic']}
🛠 Technique: {mitre['technique']} ({mitre['id']})
"""
    if geo:
        alert_summary += f"🌍 Geo Info: {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}\n"

    explanation = explain_alert(alert, return_text=True)
    recommendation = recommend_response(alert, return_text=True)

    combined = f"{alert_summary}\n\n🎯 Recommended Actions:\n{explanation}\n{recommendation}"

    console.print(Panel(combined.strip(), title="🔍 Alert & Response", border_style="cyan"))
    accumulated_alerts.append(alert)


def watch_alerts_file(filepath="/var/ossec/logs/alerts/alerts.json"):
    console.print(f"📡 Listening for new alerts in: [bold]{filepath}[/bold]")
    try:
        with open(filepath, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                try:
                    alert = json.loads(line)
                    process_alert(alert)
                except Exception as e:
                    console.print(f"⚠️ Skipped malformed alert: {e}")
    except KeyboardInterrupt:
        console.print("\n👋 Stopped watching alerts.")
        if accumulated_alerts:
            if Confirm.ask("Do you want to export all processed alerts to HTML?"):
                export_dir = os.path.join(os.getcwd(), "exports")
                os.makedirs(export_dir, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(export_dir, f"report_{timestamp}.html")
                generate_html_report(accumulated_alerts, output_path)
                console.print(f"📄 Report saved to: [bold green]{output_path}[/bold green]")
                if Confirm.ask("Open report in browser?"):
                    webbrowser.open(f"file://{output_path}")
    except FileNotFoundError:
        console.print(f"❌ File not found: [red]{filepath}[/red]")


def interactive_prompt():
    while True:
        console.rule("[bold magenta]SOCscribe Setup Wizard")
        console.print("Choose mode:\n[1] Watch\n[2] File")
        choice = Prompt.ask("Choose mode", choices=["1", "2"], default="2")

        if choice == "1":
            default_path = os.path.expanduser("~/wazuh-logs/alerts.json")
            watch_alerts_file(default_path)

        elif choice == "2":
            custom = Confirm.ask("Do you want to provide a custom file path?", default=False)
            if custom:
                filepath = Prompt.ask("Path to alert JSON file")
            else:
                filepath = os.path.expanduser("~/wazuh-logs/alerts.json")

            console.print(f"📄 Loading last alert from: {filepath}")
            try:
                with open(filepath, "r") as f:
                    lines = f.readlines()
                    if not lines:
                        console.print("⚠️ No alerts found in file.")
                        continue
                    alert = json.loads(lines[-1])
                    process_alert(alert)
            except Exception as e:
                console.print(f"❌ Failed to load alert from Wazuh log: {e}")


if __name__ == "__main__":
    interactive_prompt()
