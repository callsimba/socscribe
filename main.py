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
from rich import box

console = Console()

seen_ids = set()


def process_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = {
        "tactic": rule.get("mitre", {}).get("tactic", "Unknown"),
        "technique": rule.get("mitre", {}).get("technique", "Unknown"),
        "id": rule.get("mitre", {}).get("id", "-")
    }

    geo = alert.get("geo_info", {})

    summary = Text()
    summary.append(f"🚨 Alert ID: {alert.get('id')}\n")
    summary.append(f"🕒 Timestamp: {alert.get('timestamp')}\n")
    summary.append(f"💻 Host: {agent.get('name', 'unknown')}\n")
    summary.append(f"🌐 Source IP: {alert.get('srcip', 'N/A')}\n")
    summary.append(f"📜 Description: {rule.get('description', 'No description')}\n\n")
    summary.append(f"🧠 MITRE Tactic: {mitre['tactic']}\n")
    summary.append(f"🛠 Technique: {mitre['technique']} ({mitre['id']})\n")

    if geo:
        summary.append(f"🌍 Geo Info: {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}\n")

    console.rule("[bold cyan]🔍 Alert Summary")
    console.print(Panel(summary, box=box.ROUNDED))

    console.rule("[bold green]🎯 Recommended Actions")
    explain_alert(alert)
    recommend_response(alert)


def watch_alerts_file(filepath="/var/ossec/logs/alerts/alerts.json", level_filter=0, export_dir=None):
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
                    alert_id = alert.get("id")
                    level = alert.get("rule", {}).get("level", 0)
                    if alert_id not in seen_ids and level >= level_filter:
                        seen_ids.add(alert_id)
                        process_alert(alert)

                        if export_dir:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"alert_{timestamp}.html"
                            os.makedirs(export_dir, exist_ok=True)
                            output_path = os.path.join(export_dir, filename)
                            generate_html_report(alert, output_path)
                            console.print(f"📄 Saved: {output_path}")
                except KeyboardInterrupt:
                    if export_dir:
                        console.print("\n💾 Exporting remaining alerts before exit...")
                    break
                except Exception as e:
                    console.print(f"⚠️ Skipped malformed alert: {e}")
    except FileNotFoundError:
        console.print(f"❌ File not found: {filepath}")


def interactive_prompt():
    console.print("\n[bold green]SOCscribe Setup Wizard")
    mode = Prompt.ask("Choose mode [watch/file]", choices=["watch", "file"], default="file")

    if mode == "file":
        try:
            filepath = Prompt.ask("Path to alert JSON file")
            with open(filepath, "r") as f:
                alert = json.load(f)
            process_alert(alert)

            if Confirm.ask("Export to HTML?"):
                export_dir = Prompt.ask("Directory to save report", default="exports")
                os.makedirs(export_dir, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(export_dir, f"report_{timestamp}.html")
                generate_html_report(alert, output_path)
                console.print(f"📄 Report saved to: {output_path}")
                if Confirm.ask("Open in browser?"):
                    webbrowser.open(f"file://{os.path.abspath(output_path)}")
        except KeyboardInterrupt:
            console.print("\n❌ Cancelled. Exiting...")

    elif mode == "watch":
        try:
            filepath = Prompt.ask("Full path to Wazuh alerts.json", default="/var/ossec/logs/alerts/alerts.json")
            level = Prompt.ask("Filter by minimum alert level (1-15)?", default="0")
            export_dir = Prompt.ask("Export alerts to directory? (Leave blank to skip)", default="")
            level = int(level)
            watch_alerts_file(filepath=filepath, level_filter=level, export_dir=export_dir or None)
        except KeyboardInterrupt:
            console.print("\n🛑 Watch mode stopped. Bye!")


def main():
    parser = argparse.ArgumentParser(description="SOCscribe - SOC Alert Triage Assistant")
    parser.add_argument("parse", nargs="?", help="Path to a single alert JSON file")
    parser.add_argument("--watch", nargs="?", const="/var/ossec/logs/alerts/alerts.json", help="Live mode — optional path to alert file")
    parser.add_argument("--export", help="Directory to save HTML report (optional)")
    parser.add_argument("--open", action="store_true", help="Open report in browser after export")
    args = parser.parse_args()

    if not any(vars(args).values()):
        interactive_prompt()
        return

    if args.watch:
        watch_alerts_file(filepath=args.watch, export_dir=args.export)
        return

    if args.parse:
        try:
            with open(args.parse, "r") as f:
                alert = json.load(f)
            process_alert(alert)
            if args.export:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"report_{timestamp}.html"
                os.makedirs(args.export, exist_ok=True)
                output_path = os.path.join(args.export, filename)
                generate_html_report(alert, output_path)
                console.print(f"\n📄 Report saved to: {output_path}")
                if args.open:
                    webbrowser.open(f"file://{os.path.abspath(output_path)}")
                    console.print("🌐 Report opened in browser.")
        except Exception as e:
            console.print(f"❌ Failed to parse alert: {e}")


if __name__ == "__main__":
    main()
