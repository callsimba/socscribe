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

DEFAULT_ALERT_PATH = "/var/ossec/logs/alerts/alerts.json"

all_alerts = []


def process_alert(alert):
    all_alerts.append(alert)
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


def watch_alerts_file(filepath=DEFAULT_ALERT_PATH):
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
        console.print("\n🛑 Watch mode interrupted.")
        if Confirm.ask("Do you want to export the collected alerts to HTML?"):
            export_all_alerts()
        return
    except FileNotFoundError:
        console.print(f"❌ File not found: {filepath}")


def export_all_alerts():
    if not all_alerts:
        console.print("⚠️ No alerts to export.")
        return
    output_dir = "exports"
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"watch_report_{timestamp}.html")
    generate_html_report(all_alerts, output_path)
    console.print(f"📄 Watch session exported to: {output_path}")


def interactive_prompt():
    while True:
        console.print("\n[bold blue]SOCscribe Setup Wizard")
        mode = Prompt.ask("Choose mode", choices=["1", "2"], default="2")

        if mode == "1":
            watch_alerts_file(DEFAULT_ALERT_PATH)

        elif mode == "2":
            use_custom = Prompt.ask("Do you want to provide a custom file path? [y/n]", choices=["y", "n"], default="n")
            if use_custom == "y":
                filepath = Prompt.ask("Path to alert JSON file")
            else:
                filepath = DEFAULT_ALERT_PATH
            console.print(f"\n📄 Loading last alert from Wazuh: {filepath}")
            try:
                with open(filepath, "r") as f:
                    lines = f.readlines()
                    if not lines:
                        console.print("⚠️ No alerts found in the file.")
                        continue
                    alert = json.loads(lines[-1])
                    process_alert(alert)
            except Exception as e:
                console.print(f"❌ Failed to load alert from Wazuh log: {e}")


def main():
    try:
        interactive_prompt()
    except KeyboardInterrupt:
        console.print("\n👋 Exiting SOCscribe. Goodbye!")


if __name__ == "__main__":
    main()