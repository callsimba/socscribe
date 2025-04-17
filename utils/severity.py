# severity.py

HIGH_IDS = {
    "T1059", "T1055", "T1548", "T1053", "T1547", "T1543", "T1112", "T1110",
    "T1003", "T1105", "T1566", "T1490", "T1486", "T1218", "T1071", "T1027",
    "T1562", "T1546", "T1050", "T1203",
    "T1136", "T1114", "T1569", "T1047", "T1574"
}

MEDIUM_IDS = {
    "T1083", "T1057", "T1033", "T1012", "T1136", "T1046", "T1021",
    "T1204", "T1058", "T1540", "T1544", "T1518",
    "T1560", "T1036"
}

LOW_IDS = {
    "T1497", "T1140", "T1552", "T1595", "T1596", "T1597", "T1598"
}

def enrich_alert(alert, calculate_severity_fn):
    level = calculate_severity_fn(alert)
    ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
    ids = [tid.upper().split(".")[0] for tid in (ids if isinstance(ids, list) else [ids])]

    if any(tid in HIGH_IDS for tid in ids):
        label, reason = "High", "Critical or commonly abused ATT&CK technique"
    elif any(tid in MEDIUM_IDS for tid in ids):
        label, reason = "Medium", "Moderate‑risk ATT&CK technique"
    elif any(tid in LOW_IDS for tid in ids):
        label, reason = "Low", "Lower‑impact ATT&CK technique"
    elif level >= 6:
        label, reason = "Medium", "Behaviour‑based score ≥ 6"
    else:
        label, reason = "Low", "No strong indicators"

    alert.update(_severity_score=level,
                 _severity_label=label,
                 _severity_reason=reason)
    return alert

def get_mitre_severity(ttid: str) -> str:
    tid = ttid.upper().split(".")[0]
    if tid in HIGH_IDS:
        return "High"
    if tid in MEDIUM_IDS:
        return "Medium"
    if tid in LOW_IDS:
        return "Low"
    return "Unknown"
