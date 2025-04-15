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

DEFAULT_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"

alert_buffer = []

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
    alert_buffer.append(alert)

def watch_alerts_file(filepath=DEFAULT_ALERTS_PATH, min_level=1):
    console.print(f"📡 Listening for new alerts in: {filepath}")
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
                    if alert.get("rule", {}).get("level", 0) >= min_level:
                        process_alert(alert)
                except Exception as e:
                    console.print(f"⚠️ Skipped malformed alert: {e}")
    except FileNotFoundError:
        console.print(f"❌ File not found: {filepath}")

def run_file_mode():
    filepath = Prompt.ask("Path to alert JSON file")
    try:
        with open(filepath, "r") as f:
            alert = json.load(f)
        process_alert(alert)
        if Confirm.ask("Do you want to export this as HTML?"):
            output_dir = Prompt.ask("Export directory", default="exports")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.html"
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, filename)
            generate_html_report(alert, output_path)
            console.print(f"\n📄 Report saved to: {output_path}")
            if Confirm.ask("Open in browser?"):
                webbrowser.open(f"file://{os.path.abspath(output_path)}")
                console.print("🌐 Report opened in browser.")
    except Exception as e:
        console.print(f"❌ Failed to parse alert: {e}")

def run_watch_mode():
    level = Prompt.ask("Minimum alert level to show", default="10")
    try:
        watch_alerts_file(filepath=DEFAULT_ALERTS_PATH, min_level=int(level))
    except KeyboardInterrupt:
        console.print("\n👋 Stopped live watch mode.")
        if alert_buffer and Confirm.ask("Do you want to export all seen alerts as HTML?"):
            output_dir = Prompt.ask("Export directory", default="exports")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"live_watch_summary_{timestamp}.html"
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, filename)
            generate_html_report(alert_buffer, output_path)
            console.print(f"📄 Live watch summary saved to: {output_path}")
            if Confirm.ask("Open in browser?"):
                webbrowser.open(f"file://{os.path.abspath(output_path)}")

def interactive_prompt():
    console.print("\n[bold blue]SOCscribe Setup Wizard")
    mode = Prompt.ask("Choose mode", choices=["watch", "file"], default="file")
    if mode == "watch":
        run_watch_mode()
    else:
        run_file_mode()

def main():
    try:
        interactive_prompt()
    except KeyboardInterrupt:
        console.print("\n👋 Exiting SOCscribe. Goodbye!")

if __name__ == "__main__":
    main()
