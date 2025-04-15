import json
import argparse
from triage.explain import explain_alert
from triage.recommend import recommend_response

def main():
    parser = argparse.ArgumentParser(description="SOCscribe - SOC Alert Triage Assistant")
    parser.add_argument("parse", help="Path to the Wazuh alert JSON file")
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

    except Exception as e:
        print(f"❌ Failed to parse alert: {e}")

if __name__ == "__main__":
    main()
