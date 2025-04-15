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

console = Console()

captured_alerts = []


def format_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})
    geo = alert.get("geo_info", {})

    text = Text()
    text.append(f"🚨 Alert ID: {alert.get('id')}\n")
    text.append(f"🕒 Timestamp: {alert.get('timestamp')}\n")
    text.append(f"💻 Host: {agent.get('name', 'unknown')}\n")
    text.append(f"🌐 Source IP: {alert.get('srcip', 'N/A')}\n")
    text.append(f"📜 Description: {rule.get('description', 'No description')}\n\n")
    text.append(f"🧠 MITRE Tactic: {mitre.get('tactic', 'Unknown')}\n")
    text.append(f"🛠 Technique: {mitre.get('technique', 'Unknown')} ({mitre.get('id', '-')})\n\n")

    if geo:
        text.append(f"🌍 Geo Info: {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}\n")

    return text


def process_alert(alert):
    captured_alerts.append(alert)

    summary_text = format_alert(alert)
    console.rule("[bold cyan]🔍 Alert Summary")
    console.print(Panel(summary_text, style="cyan"))

    console.rule("[bold green]🎯 Recommended Actions")
    explain_alert(alert)
    recommend_response(alert)


def watch_alerts_file(filepath):
    print(f"📡 Listening for new alerts in: {filepath}")
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
                    print("\n👋 Stopped watching.")
                    if Confirm.ask("Do you want to export the captured alerts as HTML?"):
                        export_dir = "exports"
                        os.makedirs(export_dir, exist_ok=True)
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        out_path = os.path.join(export_dir, f"live_report_{timestamp}.html")
                        generate_html_report(captured_alerts, out_path)
                        print(f"📄 Report saved to: {out_path}")
                        if Confirm.ask("Open report in browser?"):
                            webbrowser.open(f"file://{os.path.abspath(out_path)}")
                    return
                except Exception as e:
                    print(f"⚠️ Skipped malformed alert: {e}")
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")


def interactive_prompt():
    while True:
        console.rule("[bold blue]SOCscribe Setup Wizard")
        console.print("Choose mode:\n[1] Watch\n[2] File")
        mode = Prompt.ask("Choose mode", choices=["1", "2"], default="2")

        if mode == "1":
            watch_alerts_file("/home/kali/wazuh-logs/alerts.json")

        elif mode == "2":
            use_custom = Prompt.ask("Do you want to provide a custom file path?", choices=["y", "n"], default="n")
            path = Prompt.ask("Enter path to alert JSON file") if use_custom == "y" else "/home/kali/wazuh-logs/alerts.json"

            try:
                with open(path, "r") as f:
                    lines = f.readlines()
                    last_alert = json.loads(lines[-1])
                    print(f"\n📄 Loaded alert from: {path}\n")
                    process_alert(last_alert)

                    if Confirm.ask("Export this alert to HTML?"):
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        out_path = f"exports/report_{timestamp}.html"
                        os.makedirs("exports", exist_ok=True)
                        generate_html_report(last_alert, out_path)
                        print(f"📄 Report saved to: {out_path}")
                        if Confirm.ask("Open report in browser?"):
                            webbrowser.open(f"file://{os.path.abspath(out_path)}")
            except Exception as e:
                print(f"❌ Failed to load alert from Wazuh log: {e}")


if __name__ == "__main__":
    try:
        interactive_prompt()
    except KeyboardInterrupt:
        print("\n👋 Exiting SOCscribe.")
