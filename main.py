import json
import argparse
from triage.explain import explain_alert
from triage.recommend import recommend_response
from utils.export import generate_html_report

def main():
    parser = argparse.ArgumentParser(description="SOCscribe - SOC Alert Triage Assistant")
    parser.add_argument("parse", help="Path to the Wazuh alert JSON file")
    parser.add_argument("--export", help="Path to save the HTML report (optional)", default=None)
    args = parser.parse_args()

    try:
        with open(args.parse, "r") as f:
            alert = json.load(f)

        print("\n🔍 Alert Summary:")
        print("-----------------")
        explain_alert(alert)

        print("\n🎯 Recommended Actions:")
        print("------------------------")
        recommend_response(alert)

        if args.export:
            generate_html_report(alert, args.export)
            print(f"\n📄 Report saved to: {args.export}")

    except Exception as e:
        print(f"❌ Failed to parse alert: {e}")

if __name__ == "__main__":
    main()
