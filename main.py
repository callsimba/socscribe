import json
import argparse
import os
import time
import subprocess
from datetime import datetime
from triage.explain import explain_alert
from triage.recommend import recommend_response
from utils.export import generate_html_report
import webbrowser
from rich.console import Console
from rich.text import Text
from rich.panel import Panel

console = Console()

all_alerts = []

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

    panel = Panel(text, title="🔍 Alert Summary", expand=False)
    console.print(panel)

    console.rule("[bold green]🎯 Recommended Actions")
    explain_alert(alert)
    recommend_response(alert)


def watch_alerts_file(filepath="/var/ossec/logs/alerts/alerts.json"):
    console.print(f"\n📡 Listening for new alerts in: [bold green]{filepath}[/bold green]\n")
    try:
        with open(filepath, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    alert = json.loads(line)
                    all_alerts.append(alert)
                    process_alert(alert)
                except Exception as e:
                    console.print(f"[red]⚠️ Skipped malformed alert:[/red] {e}")
    except KeyboardInterrupt:
        if all_alerts:
            export_dir = "exports"
            os.makedirs(export_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(export_dir, f"live_session_{timestamp}.html")
            generate_html_report(all_alerts, output_path)
            console.print(f"\n💾 Exported session report to: [bold cyan]{output_path}[/bold cyan]\n")
        else:
            console.print("\n⚠️ No alerts were captured during this session.")


def main():
    parser = argparse.ArgumentParser(description="SOCscribe - SOC Alert Triage Assistant")
    parser.add_argument("parse", nargs="?", help="Path to a single alert JSON file")
    parser.add_argument("--watch", nargs="?", const="/var/ossec/logs/alerts/alerts.json", help="Live mode — optional path to alert file")
    parser.add_argument("--export", help="Directory to save HTML report (optional)")
    parser.add_argument("--open", action="store_true", help="Open report in browser after export")
    args = parser.parse_args()

    if not args.watch and not args.parse:
        console.print("\n[bold yellow]Choose an option:[/bold yellow]")
        console.print("1. Live Watch Mode")
        console.print("2. Parse a Single Alert File\n")
        choice = input("Enter choice (1 or 2): ")

        if choice == "1":
            # Open watch mode in new terminal
            watch_command = f"python3 {__file__} --watch"
            subprocess.Popen(["gnome-terminal", "--", "bash", "-c", watch_command])
            console.print("\n📡 [bold green]Live watch started in new terminal[/bold green]")
            return
        elif choice == "2":
            alert_path = input("Enter path to alert JSON file: ")
            args.parse = alert_path
        else:
            console.print("[red]❌ Invalid choice. Exiting.[/red]")
            return

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
