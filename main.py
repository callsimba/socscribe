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

console = Console()

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
    print(f"📡 Listening for new alerts in: {filepath}")
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
                    print(f"⚠️ Skipped malformed alert: {e}")
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")

def main():
    parser = argparse.ArgumentParser(description="SOCscribe - SOC Alert Triage Assistant")
    parser.add_argument("parse", nargs="?", help="Path to a single alert JSON file")
    parser.add_argument("--watch", nargs="?", const="/var/ossec/logs/alerts/alerts.json", help="Live mode — optional path to alert file")
    parser.add_argument("--export", help="Directory to save HTML report (optional)")
    parser.add_argument("--open", action="store_true", help="Open report in browser after export")
    args = parser.parse_args()

    if args.watch:
        watch_alerts_file(filepath=args.watch)
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
                print(f"\n📄 Report saved to: {output_path}")

                if args.open:
                    webbrowser.open(f"file://{os.path.abspath(output_path)}")
                    print("🌐 Report opened in browser.")
        except Exception as e:
            print(f"❌ Failed to parse alert: {e}")

if __name__ == "__main__":
    main()
