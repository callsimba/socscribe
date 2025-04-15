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
from rich.text import Text
from rich.prompt import Prompt, Confirm

console = Console()

collected_alerts = []

def process_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = {
        "tactic": rule.get("mitre", {}).get("tactic", "Unknown"),
        "technique": rule.get("mitre", {}).get("technique", "Unknown"),
        "id": rule.get("mitre", {}).get("id", "-")
    }

    geo = alert.get("geo_info", {})

    text = Text()
    text.append(f"🚨 Alert ID: {alert.get('id')}\n")
    text.append(f"🕒 Timestamp: {alert.get('timestamp')}\n")
    text.append(f"💻 Host: {agent.get('name', 'unknown')}\n")
    text.append(f"🌐 Source IP: {alert.get('srcip', 'N/A')}\n")
    text.append(f"📜 Description: {rule.get('description', 'No description')}\n\n")
    text.append(f"🧠 MITRE Tactic: {mitre['tactic']}\n")
    text.append(f"🛠 Technique: {mitre['technique']} ({mitre['id']})\n")

    if geo:
        text.append(f"🌍 Geo Info: {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}\n")

    console.rule("[bold cyan]🔍 Alert Summary")
    console.print(text, style="cyan")

    console.rule("[bold green]🎯 Recommended Actions")
    explain_alert(alert)
    recommend_response(alert)

def watch_alerts_file(filepath="/var/ossec/logs/alerts/alerts.json"):
    console.print(f"\n📡 Listening for new alerts in: {filepath}")
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
                    collected_alerts.append(alert)
                    process_alert(alert)
                except Exception as e:
                    console.print(f"⚠️ Skipped malformed alert: {e}", style="yellow")
    except FileNotFoundError:
        console.print(f"❌ File not found: {filepath}", style="bold red")

def export_prompt(alerts):
    if not alerts:
        return
    if Confirm.ask("Do you want to export the alert(s) to HTML?"):
        output_dir = Prompt.ask("Directory to save HTML report", default="exports")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.html"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        generate_html_report(alerts, output_path)
        console.print(f"\n📄 Report saved to: {output_path}")
        if Confirm.ask("Open in browser?"):
            webbrowser.open(f"file://{os.path.abspath(output_path)}")
            console.print("🌐 Report opened in browser.")

def interactive_prompt():
    while True:
        console.print("\n[bold cyan]SOCscribe Setup Wizard")
        mode = Prompt.ask("Choose mode", choices=["1", "2"], default="2", show_choices=False)

        if mode == "1":  # Watch
            default_path = "/var/ossec/logs/alerts/alerts.json"
            try:
                watch_alerts_file(filepath=default_path)
            except KeyboardInterrupt:
                console.print("\n👋 Stopped live watch mode.", style="yellow")
                export_prompt(collected_alerts)
            continue

        elif mode == "2":  # File
            override = Confirm.ask("Do you want to provide a custom file path?", default=False)
            if override:
                filepath = Prompt.ask("Path to alert JSON file")
                try:
                    with open(filepath, "r") as f:
                        alert = json.load(f)
                except Exception as e:
                    console.print(f"[red]❌ Failed to load file: {e}")
                    continue
            else:
                filepath = "/var/ossec/logs/alerts/alerts.json"
                console.print(f"\n📄 Loading last alert from Wazuh: {filepath}")
                try:
                    with open(filepath, "r") as f:
                        lines = f.readlines()
                        last_line = lines[-1]
                        alert = json.loads(last_line)
                except Exception as e:
                    console.print(f"[red]❌ Failed to load alert from Wazuh log: {e}")
                    continue

            process_alert(alert)
            export_prompt([alert])

def main():
    try:
        interactive_prompt()
    except KeyboardInterrupt:
        console.print("\n👋 Exiting SOCscribe. Goodbye!", style="bold red")

if __name__ == "__main__":
    main()
