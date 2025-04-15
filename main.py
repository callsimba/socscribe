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
from rich.panel import Panel
from rich.table import Table

console = Console()

DEFAULT_WAZUH_PATH = "/home/kali/wazuh-logs/alerts.json"

watch_history = []

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


def watch_alerts_file(filepath=DEFAULT_WAZUH_PATH):
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
                    process_alert(alert)
                    watch_history.append(alert)
                except Exception as e:
                    console.print(f"⚠️ Skipped malformed alert: {e}", style="yellow")
    except FileNotFoundError:
        console.print(f"❌ File not found: {filepath}", style="bold red")


def export_watch_to_html():
    if not watch_history:
        console.print("⚠️ No alerts to export.", style="yellow")
        return
    if Confirm.ask("Do you want to export these alerts to HTML?"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("exports", exist_ok=True)
        path = f"exports/live_watch_{timestamp}.html"
        generate_html_report(watch_history, path)
        console.print(f"📄 Exported watch session to: {path}", style="green")
        if Confirm.ask("Open in browser?"):
            webbrowser.open(f"file://{os.path.abspath(path)}")


def file_mode():
    if Confirm.ask("Do you want to provide a custom file path?", default=False):
        filepath = Prompt.ask("Path to alert JSON file")
    else:
        filepath = DEFAULT_WAZUH_PATH

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
            alert = json.loads(lines[-1])
            console.print(f"\n📄 Loading last alert from Wazuh: {filepath}")
            process_alert(alert)

            if Confirm.ask("Do you want to export to HTML?"):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                os.makedirs("exports", exist_ok=True)
                path = f"exports/file_mode_{timestamp}.html"
                generate_html_report(alert, path)
                console.print(f"📄 Report saved to: {path}")
                if Confirm.ask("Open in browser?"):
                    webbrowser.open(f"file://{os.path.abspath(path)}")
    except Exception as e:
        console.print(f"❌ Failed to load alert from Wazuh log: {e}", style="bold red")


def interactive_prompt():
    while True:
        console.rule("[bold blue]SOCscribe Setup Wizard")
        console.print("Choose mode:\n[1] Watch\n[2] File")
        choice = Prompt.ask("Choose mode", choices=["1", "2"], default="2")

        if choice == "1":
            try:
                watch_alerts_file()
            except KeyboardInterrupt:
                console.print("\n👋 Watch mode stopped.", style="yellow")
                export_watch_to_html()
        elif choice == "2":
            file_mode()


def main():
    interactive_prompt()

if __name__ == "__main__":
    main()
