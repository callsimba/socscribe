from rich.console import Console
import os, json

console = Console()

def recommend_response(alert):
    rule_id = str(alert.get("rule", {}).get("id"))
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks.json')

    try:
        with open(data_path, "r") as f:
            playbooks = json.load(f)

        if rule_id in playbooks:
            for action in playbooks[rule_id]["actions"]:
                console.print(f"[green]- {action}[/]")
        else:
            console.print("[yellow]- No specific playbook found for this rule.")
            console.print("[yellow]- Review logs, check user/process/IP behavior manually.")
    except Exception as e:
        console.print(f"[red]❌ Error loading playbooks: {e}")
