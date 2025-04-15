from rich.console import Console
from rich.text import Text
from utils.eventid_map import get_event_description
from .ai_describer import get_dynamic_description

console = Console()

# Utility: Flatten nested dict with dot notation
def flatten_dict(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

# Explanation logic for keys and values
def get_field_explanation(key, value):
    key = key.lower()
    value = str(value).lower()

    # Key-specific explanations
    if "agent.name" in key:
        return "This is the hostname of the endpoint that generated the alert."
    elif "rule.description" in key:
        if "powershell" in value:
            return "PowerShell was used — a common technique for running scripts or payloads."
        elif "cmd" in value:
            return "Command Prompt activity — may indicate manual execution or script usage."
        return "Describes what triggered the alert. Look closely — this can reveal suspicious behavior."
    elif "data.win.system.eventid" in key:
        return get_event_description(value)
    elif "mitre.tactic" in key:
        return "This is the high-level objective of the attacker, like Execution or Persistence."
    elif "mitre.technique" in key:
        return "The specific method used to carry out the tactic, such as PowerShell or Registry Run Keys."
    elif "srcip" in key:
        return "The source IP address where the traffic or event originated."
    elif "geoip" in key:
        return "Geolocation info derived from IP address — shows country, city, ISP, etc."
    elif "user.name" in key:
        return "This is the username associated with the event. May help trace attacker identity."
    elif "process.name" in key:
        return "The name of the process that triggered this alert. Useful in identifying suspicious binaries."
    elif "win.system.providerName" in key:
        return "The name of the Windows event provider that logged this event."
    elif "win.system.task" in key:
        return "Windows Event Log task — shows what kind of activity was performed."
    elif "win.system.level" in key:
        return "Indicates severity — higher means more critical."
    elif "rule.groups" in key:
        return "Indicates the rule category — such as malware, system, audit, etc."

    # Fallback to ChatGPT if no match found above
    return get_dynamic_description(key, value)

# Main alert explanation

def explain_alert(alert, return_text=False):
    flat_alert = flatten_dict(alert)
    text = Text()

    for key, value in flat_alert.items():
        text.append(f"\n🔹 {key}: {value}\n")
        explanation = get_field_explanation(key, value)
        text.append(f"    ➤ What does this mean? {explanation}\n")

    console.print(text)

    if return_text:
        return text.plain

