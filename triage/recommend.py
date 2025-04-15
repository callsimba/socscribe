import json
import os

def recommend_response(alert):
    rule_id = str(alert.get("rule", {}).get("id"))
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks.json')

    try:
        with open(data_path, "r") as f:
            playbooks = json.load(f)

        if rule_id in playbooks:
            for action in playbooks[rule_id]["actions"]:
                print(f"- {action}")
        else:
            print("- No specific playbook found for this rule.")
            print("- Review logs, check user/process/IP behavior manually.")
    except Exception as e:
        print(f"❌ Error loading playbooks: {e}")
