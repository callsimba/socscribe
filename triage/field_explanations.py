field_explanations = {
  # ——— CORE AGENT / HOST INFO ———
  "agent.id": "Internal numeric ID that Wazuh gives the endpoint. Use it to look up that machine in the agent list.",
  "agent.name": "Hostname of the source machine. Handy when matching with AD or your CMDB.",
  "agent.ip": "The IP address seen by Wazuh. Public or unknown private ranges are red‑flags for pivots.",

  # ——— GENERIC ALERT METADATA ———
  "timestamp": "When this log was created. The SOC timeline starts here – always line this up with other events.",
  "id": "Wazuh’s unique alert ID. Pop it in Kibana to pull the raw doc in one click.",
  "full_log": "The complete raw log message before parsing – last‑resort truth for deep dives.",
  "location": "Which log source produced the event (e.g., sysmon, auditd).",
  "input.type": "Collector that grabbed the log (logcollector, syscheck, etc.).",
  "manager.name": "Name of the Wazuh manager node that processed the alert – useful in multi‑node clusters.",

  # ——— RULE CORE ———
  "rule.id": "Numeric ID of the detection rule that fired.",
  "rule.level": "Original Wazuh severity 0‑15. 0‑3 = info, 4‑7 = suspicious, 8+ = bad.",
  "rule.description": "Human‑readable summary of why the rule fired. Read this first—treat it as the alert’s headline.",
  "rule.groups": "Tags attached to the rule (malware, sysmon_eid1, etc.). Handy for quick pivots.",
  "rule.firedtimes": "How many times this exact rule hit during aggregation. High = repetitive behaviour.",
  "rule.mail": "True if the rule is configured to email someone – legacy but can warn you of high value detections.",

  # – Compliance flags (surface only) –
  "rule.cis": "Maps to CIS benchmark controls – governance folks love this.",
  "rule.hipaa": "HIPAA mapping – healthcare data exposure.",
  "rule.pci_dss": "PCI DSS mapping – card‑holder data rules.",
  "rule.nist_800_53": "NIST 800‑53 mapping – US Fed controls.",
  "rule.gdpr": "General Data Protection Regulation relevance.",
  "rule.tsc": "SOC‑2 Trust Services Criteria tag.",

  # ——— MITRE ———
  "rule.mitre.id": "List of ATT&CK IDs matched (e.g., T1059). If you see High‑risk IDs like T1059, T1105, T1547, act fast.",
  "rule.mitre.tactic": "ATT&CK goal category (Execution, Priv‑Esc, etc.). Tells you WHY an attacker is doing this.",
  "rule.mitre.technique": "Specific technique name (e.g., PowerShell). Shows the HOW.",

  # ——— CUSTOM SEVERITY WE ADD ———
  "_severity_score": "Score 0‑10 our script assigns. 0‑4 = low noise, 5‑7 = check soon, 8‑10 = priority.",
  "_severity_label": "High / Medium / Low as derived from the score & MITRE list.",
  "_severity_reason": "Short human reason we chose that label.",

  # ——— SCA (SECURITY CONFIG) TOP‑LEVEL ———
  "data.sca.failed": "Number of failed checks in the scan. Lots of red means poor hygiene.",
  "data.sca.passed": "Checks that were green – a quick confidence boost.",
  "data.sca.invalid": "Checks that couldn’t run (permissions, missing file, etc.).",
  "data.sca.score": "Overall compliance score 0‑100%. Under 85% usually needs remediation.",
  "data.sca.total_checks": "Total tests executed this run.",
  "data.sca.policy": "Name of the benchmark policy (e.g., CIS Ubuntu 20.04).",
  "data.sca.policy_id": "Internal numeric ID for that policy.",
  "data.sca.scan_id": "Session ID grouping all checks from the same run.",
  "data.sca.type": "Scan engine type (script, registry, pkg). Good to know when writing fixes.",

  # ——— Individual SCA check fields (most common) ———
  "data.sca.check.id": "Unique ID for this single check – copy to search historic runs.",
  "data.sca.check.title": "Headline of the secure‑config test (e.g., ‘Ensure password max‑age ≤ 365’).",
  "data.sca.check.description": "Detailed what/why of the check – great learning resource.",
  "data.sca.check.command": "Shell/registry query used in the test – reproduce it yourself when verifying.",
  "data.sca.check.result": "PASS or FAIL. Red = needs fixing.",
  "data.sca.check.previous_result": "Last run’s pass/fail – trend spotting for drift.",
  "data.sca.check.remediation": "Vendor‑recommended fix text – copy‑paste for hardening tickets.",
  "data.sca.check.rationale": "Why this matters (compliance / security impact).",
  "data.sca.check.references": "Links to external docs / standards backing the check.",

  # ——— Extra high‑frequency generic data.* ———
  "data.arch": "System CPU architecture (x64, ARM). Helps pick correct malware sample or patch.",
  "data.dpkg_status": "Result of dpkg query on Debian – often ‘not‑installed’, ‘config‑files’, etc.",
  "data.file": "Generic file path referenced in the log.",
  "data.level": "Sometimes reused by custom decoders for ad‑hoc severity – treat with caution.",
  "data.package": "Package name involved (apt/yum). Good for vuln tracking.",
  "data.srcport": "Source TCP/UDP port seen – can confirm outbound SMB / RDP, etc.",
  "data.srcuser": "User on the originating host – watch for root / SYSTEM used remotely.",
  "data.status": "Result status (success / failure). Quick win to see brute force vs success.",
  "data.uid": "Numeric user ID – pairs with username when name missing.",
  "data.title": "Short title some decoders add – usually informational.",
  "data.extra_data": "Raw extra block – drill in if the summary is unclear.",

  # ——— WINDOWS EVENTDATA (additions) ———
  "data.win.eventdata.attachedFiles": "Names of files carried inside the event (e.g., suspicious attachments).",
  "data.win.eventdata.bucket": "Custom correlation bucket tag – helps grouping noisy events.",
  "data.win.eventdata.bucketType": "Type of bucket (IP, user, process).",
  "data.win.eventdata.stage": "EDR stage (Pre / Post) so you know if the action was blocked or just logged.",
  "data.win.eventdata.response": "EDR response (blocked / allowed).",
  "data.win.eventdata.keyLength": "Key length used during logon (e.g., 128‑bit). Weak keys = downgrade attacks.",
  "data.win.eventdata.url": "URL accessed or embedded in the event – plug into reputation feeds.",

  # ——— WINDOWS SYSTEM FIELDS (additions) ———
  "data.win.system.keywords": "Bit‑flag keywords set by Windows – rarely critical but good for filtering.",
  "data.win.system.opcode": "Low‑level opcode number (start/stop). Only needed in deep forensics.",
  "data.win.system.task": "Windows task category (Logon, Policy Change, etc.).",
  "data.win.system.eventID": "Classic Windows Event ID (4624, 4688, etc.). Learn the big ones!",
  "data.win.system.eventRecordID": "Incremental log record number – handy for timeline order.",
  "data.win.system.severityValue": "TEXT severity (INFO, WARNING, ERROR).",

  # ——— DECODER / PREDECODER ———
  "decoder.name": "Name of the Wazuh decoder that parsed this raw log.",
  "decoder.parent": "Parent decoder used – for nested parsing.",
  "predecoder.program_name": "Process that originally wrote the log line (e.g., sshd, sudo).",

  # ——— SYSHECK / FIM extras ———
  "syscheck.changed_attributes": "Comma list of file attributes altered (size, perms).",

  # ——— SPECIAL SCRIPT SEVERITY ———
  "data.scrip": "(typo) Original script name – often safe to ignore.",

  # Catch‑all default
  "*DEFAULT*": "No explanation yet – likely niche or custom. Treat like raw data until the team documents it."
}

def get_field_explanation(field_name):
    return field_explanations.get(field_name, field_explanations.get("*DEFAULT*"))
