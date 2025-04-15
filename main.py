import json
import argparse
import os
import time
from datetime import datetime
from triage.explain import explain_alert
from triage.recommend import recommend_response
from utils.export import generate_html_report
from rich.console import Console
from rich.text import Text
from rich.prompt import Prompt, Confirm
import webbrowser

console = Console()
DEFAULT_ALERT_PATH = os.path.expanduser("~/wazuh-logs/alerts.json")

# Store seen alerts to avoid duplicates
seen_alert_ids = set()
buffered_alerts = []


def process_alert(alert):
    alert_id = alert.get("id")
    if alert_id in seen_alert_ids:
        return
    seen_alert_ids.add(alert_id)
    buffered_alerts.append(alert)

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


def watch_alerts_file(filepath):
    console.print(f"📡 Listening for new alerts in: {filepath}")
    try:
        with open(filepath, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                try:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    alert = json.loads(line)
                    process_alert(alert)
                except KeyboardInterrupt:
                    console.print("\n👋 Stopping live watch...")
                    if Confirm.ask("Do you want to export the alerts to HTML?"):
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"watch_report_{timestamp}.html"
                        output_path = os.path.join("exports", filename)
                        os.makedirs("exports", exist_ok=True)
                        generate_html_report(buffered_alerts, output_path)
                        console.print(f"📄 Report saved to: {output_path}")
                        if Confirm.ask("Open report in browser?"):
                            webbrowser.open(f"file://{os.path.abspath(output_path)}")
                    return
                except Exception as e:
                    console.print(f"⚠️ Skipped malformed alert: {e}")
    except FileNotFoundError:
        console.print(f"❌ File not found: {filepath}")


def interactive_prompt():
    while True:
        console.rule("[bold magenta]SOCscribe Setup Wizard")
        mode = Prompt.ask("Choose mode", choices=["1", "2"], default="2")

        if mode == "1":
            watch_alerts_file(DEFAULT_ALERT_PATH)
        else:
            custom_path = Confirm.ask("Do you want to provide a custom file path?", default=False)
            if custom_path:
                filepath = Prompt.ask("Full path to alert JSON file")
            else:
                filepath = DEFAULT_ALERT_PATH
                console.print(f"\n📄 Loading last alert from Wazuh: {filepath}")

            try:
                with open(filepath, "r") as f:
                    lines = f.readlines()
                    alert = json.loads(lines[-1])
                    process_alert(alert)

                    if Confirm.ask("Do you want to export this to HTML?"):
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"file_report_{timestamp}.html"
                        output_path = os.path.join("exports", filename)
                        os.makedirs("exports", exist_ok=True)
                        generate_html_report(alert, output_path)
                        console.print(f"📄 Report saved to: {output_path}")
                        if Confirm.ask("Open report in browser?"):
                            webbrowser.open(f"file://{os.path.abspath(output_path)}")
            except Exception as e:
                console.print(f"❌ Failed to load alert from Wazuh log: {e}")


def main():
    try:
        interactive_prompt()
    except KeyboardInterrupt:
        console.print("\n👋 Exiting SOCscribe...")


if __name__ == "__main__":
    main()
