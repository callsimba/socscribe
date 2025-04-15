field_explanations = {
    "agent.id": "The unique identifier assigned to the endpoint agent. Helps track which system triggered the alert. Not sensitive by itself but important for correlation.",
    "agent.name": "The hostname of the system where the alert was generated. If you see a name you don't recognize or that's outside your environment naming scheme, be alert.",
    "agent.ip": "The IP address of the endpoint. If it's internal (like 192.168.x.x), it's probably normal. Public IPs should raise suspicion, especially if they're not whitelisted.",

    "manager.name": "The Wazuh manager that received and processed this alert. Usually your SIEM or security platform. Nothing to worry about unless unknown.",
    "decoder.name": "The Wazuh decoder used to parse the raw log message. Useful for tracing which logs are generating the most noise or alerts.",

    "rule.id": "The ID of the rule that triggered the alert. Lower numbers are often built-in; custom ones may vary in reliability.",
    "rule.level": "Alert severity level (0–15). 0–3 = Info/Low, 4–7 = Medium, 8+ = High. Anything above 8 should be reviewed immediately.",
    "rule.description": "A short summary of what triggered the alert. Focus here for initial triage clues — keywords like 'PowerShell', 'EncodedCommand', or 'Suspicious Login' should grab your attention.",
    "rule.groups": "Tags assigned to this rule. Examples: 'windows', 'malware', 'auth_failed'. Look for terms like 'persistence', 'privilege', 'lateral' as warning signs.",
    "rule.firedtimes": "How many times this rule has been triggered recently. High values (5+) could indicate repetitive abuse or automation.",
    "rule.mail": "True/False. If true, this alert is configured to notify via email — meaning it’s high value.",
    "rule.gdpr": "GDPR compliance mapping. If triggered, the alert may involve personal or sensitive data.",
    "rule.hipaa": "HIPAA compliance mapping. Triggers might involve healthcare-related privacy risks.",
    "rule.nist_800_53": "NIST control mapping. Helps classify alert in standardized security frameworks.",
    "rule.pci_dss": "PCI compliance mapping. Watch this if you're securing financial or payment data.",
    "rule.tsc": "SOC 2 Trust Service Criteria reference. Useful in audits and risk mapping.",

    "rule.mitre.id": "MITRE ATT&CK technique ID. Learn these if you're doing threat hunting — T1059 = PowerShell, T1078 = Valid Accounts, etc.",
    "rule.mitre.tactic": "The attacker’s broader goal — like 'Privilege Escalation' or 'Persistence'. These tell you what stage of the attack this is.",
    "rule.mitre.technique": "The specific method used — e.g., 'Scripting', 'Registry Run Keys'. Memorize key techniques for faster triage.",

    "timestamp": "When the alert was generated. Useful for aligning with user behavior, known incidents, or other logs.",
    "id": "A unique alert ID used for log correlation. Use it for searching related logs in ELK or Wazuh dashboards.",

    "location": "The source component (like 'sysmon', 'eventchannel'). Watch for logs from unknown locations or custom log sources.",
    "full_log": "The raw log string. Use it for full context — can reveal decoded scripts, file paths, or command lines.",

    "data.win.system.eventID": "The Windows Event ID. Common: 4624 = Login Success, 4625 = Failed Login, 7045 = Service Installed. Research uncommon IDs.",
    "data.win.system.channel": "The log channel (e.g., System, Security). 'Security' channel is most critical for SOC work.",
    "data.win.system.level": "Windows log severity (1–5). 1 = Critical, 2 = Error, 3 = Warning, 4 = Info, 5 = Verbose. Focus on 1–2 first.",
    "data.win.system.message": "Detailed log message. Look for signs of attack — e.g., 'net.exe', 'rundll32', 'powershell.exe', or encoded strings.",
    "data.win.system.opcode": "The type of operation performed. Usually low-level. Can often be ignored unless you're deep in detection tuning.",
    "data.win.system.processID": "The numeric ID of the process. Match this with known malicious tools or correlate with parent process.",
    "data.win.system.threadID": "Like process ID but for threads. Rarely useful alone — better used for forensic timeline correlation.",
    "data.win.system.providerName": "The Windows component that generated the event — like 'Microsoft-Windows-Security-Auditing'. Unusual providers may indicate tampering.",
    "data.win.system.providerGuid": "Globally unique ID for the provider. Only useful for extremely detailed audit work.",
    "data.win.system.systemTime": "The time the system recorded the event. Use this for correlation with other tools (like Defender, CrowdStrike).",
    "data.win.system.task": "Task category of the event. 'Logon', 'Process Creation', etc. Useful for identifying attacker movement.",
    "data.win.system.version": "Schema version for the log — rarely relevant unless parsing fails.",
    "data.win.system.eventRecordID": "Sequence number in the Event Log. Helps trace exact ordering of actions.",
    "data.win.system.keywords": "Used for log filtering. Not critical in triage.",
    "data.win.system.computer": "The computer hostname. Cross-check with agent.name to ensure consistency.",
    "data.win.system.severityValue": "Severity like 'INFO', 'ERROR', or 'WARNING'. Focus on 'ERROR' or 'CRITICAL' first.",

    "data.win.eventdata.commandLine": "The full command used by a process. Red flags: 'powershell.exe', 'cmd.exe', 'encodedCommand', 'downloadString'.",
    "data.win.eventdata.image": "The binary path. Watch for binaries in unusual directories like temp folders.",
    "data.win.eventdata.parentImage": "The parent process. If a legit tool like 'explorer.exe' spawns PowerShell, it’s suspicious.",
    "data.win.eventdata.parentCommandLine": "Command that launched the parent process. Helps trace attack chains.",
    "data.win.eventdata.user": "The username that ran the process. If 'SYSTEM' or 'NT AUTHORITY' is involved in non-system tasks — be alert.",
    "data.win.eventdata.logonGuid": "Correlates events in a single logon session. Useful for lateral movement detection.",
    "data.win.eventdata.logonId": "The logon session number. Use with logon type to validate activity.",
    "data.win.eventdata.hashes": "Hashes of the binary. SHA256 is most important. Paste into VirusTotal to check for malware.",
    "data.win.eventdata.integrityLevel": "Tells you the security context: Low = sandbox, Medium = user, High = admin. Unexpected High = potential privilege escalation.",
    "data.win.eventdata.parentUser": "Who ran the parent process. Used for tracking user behavior chains.",

    "GeoInfo": "IP geolocation. If the alert shows foreign countries or unknown ISPs, investigate for external attacks."
}

def get_field_explanation(field_name):
    return field_explanations.get(field_name, "No explanation available for this field yet.")
