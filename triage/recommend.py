from rich.console import Console
import os, json

console = Console()

def recommend_response(alert, return_text=False):
    rule_id = str(alert.get("rule", {}).get("id"))
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks.json')

    output = []

    try:
        with open(data_path, "r") as f:
            playbooks = json.load(f)

        if rule_id in playbooks:
            for action in playbooks[rule_id]["actions"]:
                line = f"- {action}"
                if return_text:
                    output.append(line)
                else:
                    console.print(f"[green]{line}[/]")
        else:
            fallback = [
                "- No specific playbook found for this rule.",
                "- Review logs, check user/process/IP behavior manually."
            ]
            for line in fallback:
                if return_text:
                    output.append(line)
                else:
                    console.print(f"[yellow]{line}[/]")
    except Exception as e:
        msg = f" Error loading playbooks: {e}"
        if return_text:
            output.append(msg)
        else:
            console.print(f"[red]{msg}[/]")

    if return_text:
        return "\n".join(output)
