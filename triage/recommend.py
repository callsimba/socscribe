import json, os, textwrap
from rich.console import Console
from utils.mitre_index import get_investigation_tips

console = Console()
PLAYBOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "playbooks.json")

# Fallback play‑books per MITRE tactic  ✱  Keep these short & editable
TACTIC_LIBRARY = {
    "execution": {
        "goal": "A process or script was launched on the host.",
        "play": [
            "Capture full command‑line, parent‑child process tree and hashes.",
            "Pull a live memory sample or EDR triage package for the PID.",
            "If script is unsigned or obfuscated ➜ *contain* host from network.",
            "Ask end‑user (or ticket) to confirm if the action was expected."
        ]
    },
    "privilege escalation": {
        "goal": "An account or process gained elevated privileges.",
        "play": [
            "Identify *who/what* received elevation and via which mechanism.",
            "Search for matching logon events (4624/4672, etc.) on peer hosts.",
            "Reset or disable the affected account if elevation is unauthorised.",
            "Check for persistence (scheduled tasks, services, run‑keys)."
        ]
    },
    "persistence": {
        "goal": "Attacker created a foothold that survives reboot.",
        "play": [
            "Locate newly‑added autostart registry keys or services.",
            "Compare with baseline autoruns; remove unknown entries.",
            "Hunt for matching artefacts on sibling hosts."
        ]
    },
    # …add more tactics as you grow…
}

# How urgent / who owns it
PRIORITY = {
    "High":   ("🚨  **High‑priority** – escalate to IR Lead *immediately*", "Incident‑Response Lead"),
    "Medium": ("⚠️  **Medium‑priority** – Tier 2 review within 60 min",      "Tier 2 SOC Analyst"),
    "Low":    ("ℹ️  **Low‑priority** – Tier 1 review in normal queue",       "Tier 1 SOC Analyst")
}

def _emit(line, return_text, bucket):
    if return_text:
        bucket.append(textwrap.fill(line, width=100))
    else:
        console.print(line)

def recommend_response(alert, return_text: bool=False):
    """
    Build a rich, multi‑step response plan for the supplied alert
    (prints with colours via Rich **or** returns newline‑joined text for HTML export).
    """
    out = []
    rule      = alert.get("rule", {})
    rule_id   = str(rule.get("id", ""))
    mitre_ids = rule.get("mitre", {}).get("id", []) or []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    tactic    = (rule.get("mitre", {}).get("tactic") or [""]).lower()
    tactic    = tactic[0] if isinstance(tactic, list) else tactic
    sev       = alert.get("_severity_label", "Low")

    # ------------------------------------------------– Load playbooks
    try:
        with open(PLAYBOOK_PATH, "r") as fp:
            playbooks = json.load(fp)
    except Exception as e:
        playbooks = {}
        _emit(f"[red]✖  Could not load playbooks.json ➜ {e}[/]", return_text, out)

    # ------------------------------------------------– Build actions list
    actions = None

    # 1️⃣ exact rule ID
    if rule_id and rule_id in playbooks:
        actions = playbooks[rule_id]["actions"]

    # 2️⃣ any MITRE technique ID
    if not actions:
        for tid in mitre_ids:
            if tid in playbooks:
                actions = playbooks[tid]["actions"]
                break

    # 3️⃣ tactic library
    if not actions and tactic in TACTIC_LIBRARY:
        lib = TACTIC_LIBRARY[tactic]
        actions = [
            f"**Objective →** {lib['goal']}",
            *lib["play"]
        ]

    # 4️⃣ generic fallback
    if not actions:
        actions = [
            "⚙️  **Generic Response Template**",
            "1. Collect related logs & artefacts (EDR, Sysmon, firewall).",
            "2. Validate if the behaviour is authorised or expected.",
            "3. If suspicious ➜ isolate host, reset credentials, block IoCs.",
            "4. Document findings and escalate to Team Lead if needed."
        ]

    # ------------------------------------------------– Render
    prio_line, owner = PRIORITY.get(sev, ("ℹ️  Review when possible", "Tier 1 SOC Analyst"))
    _emit(prio_line, return_text, out)
    _emit(f"**Ownership:** {owner}", return_text, out)
    _emit("", return_text, out)

    for step in actions:
        if isinstance(step, str) and step.startswith("**Objective"):
            _emit(step, return_text, out)
        else:
            _emit(f"- {step}", return_text, out)

    # quick links (investigation tips) at the bottom
    for tid in mitre_ids:
        tips = get_investigation_tips(tid)
        link = f"https://attack.mitre.org/techniques/{tid}"
        _emit(f"\n🔗 *Investigation cheat‑sheet for* [{tid}]({link}):", return_text, out)
        for w in tips["what"]:
            _emit(f"   • {w}", return_text, out)

    return "\n".join(out) if return_text else None
