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
from rich.prompt import Prompt, IntPrompt, Confirm
import webbrowser

console = Console()

def process_alert(alert, seen_ids=None):
    if seen_ids is not None and alert.get("id") in seen_ids:
        return  # Skip duplicates

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = {
        "tactic": rule.get("mitre", {}).get("tactic", "Unknown"),
        "technique": rule.get("mitre", {}).get("technique", "Unknown"),
        "id": rule.get("mitre", {}).get("id", "-")
    }

    geo = alert.get("geo_info", {})

    text = Text()
    text.append(f"\n🚨 Alert ID: {alert.get('id')}\n")
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

    if seen_ids is not None:
        seen_ids.add(alert.get("id"))

def watch_alerts_file(filepath, export_dir=None, filter_level=None):
    seen_ids = set()
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
                    level = alert.get("rule", {}).get("level", 0)
                    if filter_level and level < filter_level:
                        continue
                    process_alert(alert, seen_ids)

                    if export_dir:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"alert_{timestamp}.html"
                        os.makedirs(export_dir, exist_ok=True)
                        generate_html_report(alert, os.path.join(export_dir, filename))

                except Exception as e:
                    console.print(f"⚠️ Skipped malformed alert: {e}")
    except FileNotFoundError:
        console.print(f"❌ File not found: {filepath}")

def interactive_prompt():
    console.print("\n[bold cyan]SOCscribe Setup Wizard[/bold cyan]")

    mode = Prompt.ask("Choose mode", choices=["watch", "file"], default="file")

    if mode == "watch":
        filepath = Prompt.ask("Path to live alerts JSON file", default="/var/ossec/logs/alerts/alerts.json")
        level_choice = IntPrompt.ask("Filter level (1=critical only, 5=medium and up, 10=all)", default=10)
        export = Confirm.ask("Export each alert to HTML?", default=False)
        export_dir = Prompt.ask("Export directory", default="exports") if export else None
        watch_alerts_file(filepath, export_dir, level_choice)
    else:
        filepath = Prompt.ask("Path to alert JSON file")
        if not os.path.isfile(filepath):
            console.print(f"❌ File not found: {filepath}")
            return
        level_choice = IntPrompt.ask("Minimum level to include (optional, press Enter to skip)", default=0)
        with open(filepath, "r") as f:
            alert = json.load(f)
        if alert.get("rule", {}).get("level", 0) < level_choice:
            console.print("🚫 Alert below selected level.")
            return

        process_alert(alert)

        if Confirm.ask("Export to HTML?", default=True):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Prompt.ask("Export directory", default="exports")
            os.makedirs(output_dir, exist_ok=True)
            outpath = os.path.join(output_dir, f"report_{timestamp}.html")
            generate_html_report(alert, outpath)
            console.print(f"✅ Report saved to: {outpath}")
            if Confirm.ask("Open in browser?", default=False):
                webbrowser.open(f"file://{os.path.abspath(outpath)}")

if __name__ == "__main__":
    interactive_prompt()