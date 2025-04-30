import os
import json
from utils.custom_tactics import custom_tactics


MITRE_LOOKUP = {}

def resolve_parent_ttid(ttid: str) -> str:
    return ttid.split('.')[0] if '.' in ttid else ttid

def load_mitre_data():
    path = os.path.join(os.path.dirname(__file__), "../mitre.json")
    with open(path, "r") as f:
        data = json.load(f)

    for technique in data.get("techniques", []):
        tid = technique.get("external_id", "").upper()

        
        if not tid:
            refs = technique.get("external_references", [])
            for ref in refs:
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id", "").upper()
                    break

        name = technique.get("name", "")
        tactic = technique.get("tactic", "").lower()

        if tid:
            MITRE_LOOKUP[tid] = {
                "name": name,
                "tactic": tactic
            }


load_mitre_data()


TACTIC_INVESTIGATION_MAP = {
    "reconnaissance": {
        "what": [
            "Look for scanning tools (e.g., nmap, masscan)",
            "Check for DNS queries or external lookups",
            "Identify user-agents or automation patterns"
        ],
        "where": [
            "DNS logs, proxy logs, firewall logs",
            "Web server access logs",
            "Sysmon: Event ID 3 (network connections)"
        ]
    },
    "resource development": {
        "what": [
            "Identify cloud, GitHub, or GitLab staging activity",
            "Detect new domain registrations or external infrastructure",
            "Look for malicious uploads in forums or code repos"
        ],
        "where": [
            "Threat intel feeds",
            "Cloud build/deploy logs",
            "Email and web monitoring logs"
        ]
    },
    "initial access": {
        "what": [
            "Check for brute-force, phishing, or external service exploitation",
            "Look at VPN, RDP, and email access attempts",
            "Review suspicious binaries dropped by user"
        ],
        "where": [
            "Windows: Event IDs 4625 (failed logon), 4624 (success)",
            "Firewall, VPN logs",
            "Mail gateways, browser activity logs"
        ]
    },
    "execution": {
        "what": [
            "Analyze command line usage and script interpreters",
            "Detect execution of encoded or obfuscated commands",
            "Check parent-child process chains"
        ],
        "where": [
            "Windows: Event ID 4688",
            "Sysmon: Event IDs 1, 11, 4104",
            "Wazuh: data.win.eventdata.commandLine"
        ]
    },
    "persistence": {
        "what": [
            "Detect autostart registry key modifications",
            "Check for new scheduled tasks or services",
            "Look for unsigned or oddly-named startup binaries"
        ],
        "where": [
            "Sysmon: Event IDs 12–14 (registry)",
            "Event ID 4698 (scheduled task created)",
            "Autoruns baseline comparisons"
        ]
    },
    "privilege escalation": {
        "what": [
            "Look for token impersonation or UAC bypass",
            "Detect use of privilege escalation tools or exploits",
            "Check for processes gaining SYSTEM level access"
        ],
        "where": [
            "Sysmon: Event ID 1 (process creation), 10 (process access)",
            "Windows: Event ID 4672 (privileges assigned)",
            "Security logs and UAC elevation logs"
        ]
    },
    "defense evasion": {
        "what": [
            "Review signs of logging being disabled",
            "Detect AMSI or ETW bypass techniques",
            "Monitor PowerShell with missing or empty logs"
        ],
        "where": [
            "Sysmon & Wazuh command logging",
            "Security event logs with gaps",
            "Endpoint protection/AV logs"
        ]
    },
    "credential access": {
        "what": [
            "Detect LSASS access or memory dumps",
            "Identify usage of tools like Mimikatz or pwdump",
            "Watch for SAM/SECURITY hive access"
        ],
        "where": [
            "Windows: Event IDs 4656, 4663 (handle access)",
            "Sysmon: Event ID 10 (process access)",
            "Registry access and dump files"
        ]
    },
    "discovery": {
        "what": [
            "Detect enumeration of users, groups, AD objects",
            "Watch for large bursts of share/network lookups",
            "Inspect use of built-in discovery tools"
        ],
        "where": [
            "Sysmon: Event IDs 1, 3",
            "Windows: Event ID 4662",
            "Wazuh: net.exe, whoami, nltest command tracking"
        ]
    },
    "lateral movement": {
        "what": [
            "Trace remote service or scheduled task creation",
            "Detect RDP/PsExec/WMI logons and executions",
            "Check for token or session reuse across systems"
        ],
        "where": [
            "Windows: Event ID 4624 (logon type 3 or 10)",
            "Sysmon: Event ID 3 (network), 11 (file), 1 (proc)",
            "Wazuh: commandLine with 'psexec', 'wmic'"
        ]
    },
    "collection": {
        "what": [
            "Detect screen capture or clipboard activity",
            "Check for keyloggers or document staging",
            "Identify archive creation in temp folders"
        ],
        "where": [
            "Sysmon: Event ID 11 (file create), 13 (registry access)",
            "Wazuh: file write alerts to ZIP/7z/RAR files",
            "Clipboard event logs (if enabled)"
        ]
    },
    "command and control": {
        "what": [
            "Check for beaconing patterns or data exfil",
            "Detect DNS, HTTPS, or reverse shell callbacks",
            "Inspect command decoding and payload download"
        ],
        "where": [
            "Firewall/Proxy logs",
            "Sysmon: Event ID 3 (outbound IPs)",
            "Event logs + PowerShell (Invoke-WebRequest, -enc)"
        ]
    },
    "exfiltration": {
        "what": [
            "Trace creation of large archives or encrypted transfers",
            "Check usage of cloud sync tools",
            "Monitor unexpected outbound traffic spikes"
        ],
        "where": [
            "Sysmon: Event ID 11, 3",
            "Cloud drive sync logs",
            "NetFlow, proxy, and egress filters"
        ]
    },
    "impact": {
        "what": [
            "Detect file deletion, encryption, or wiping",
            "Look for dropped ransom notes or destructive commands",
            "Check VSS activity (shadow copies, backups)"
        ],
        "where": [
            "Sysmon: Event ID 23 (file delete)",
            "Windows: Event ID 524, 1102",
            "Tool detection: vssadmin, cipher, sdelete"
        ]
    }
}

def get_investigation_tips(ttid: str):
    if isinstance(ttid, list):
        ttid = ttid[0]
    ttid = ttid.upper()

    parent_id = resolve_parent_ttid(ttid)

    if parent_id in custom_tactics:
        return {
            "title": custom_tactics[parent_id]["title"],
            "what": custom_tactics[parent_id]["what"],
            "where": custom_tactics[parent_id]["where"]
        }

    mitre_entry = MITRE_LOOKUP.get(parent_id)

    if not mitre_entry:
        return {
            "title": f"{ttid}",
            "what": ["No investigation steps available."],
            "where": ["No known log sources or registry paths."]
        }

    tactic = mitre_entry.get("tactic", "")
    title = mitre_entry.get("name", "")
    fallback = TACTIC_INVESTIGATION_MAP.get(tactic.lower(), {})

    return {
        "title": f"{ttid} – {title}",
        "what": fallback.get("what", ["No actionable items."]),
        "where": fallback.get("where", ["No sources defined."])
    }
