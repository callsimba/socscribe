
def explain_sysmon_event(event_id: str) -> dict:
    map = {
        "1": {
            "description": "Process creation (e.g., malware spawning cmd.exe or powershell.exe).",
            "detection_tip": "Look for suspicious parent-child process pairs (e.g., Word spawning PowerShell).",
            "mitre_id": "T1059",
            "mitre_technique": "Command and Scripting Interpreter"
        },
        "3": {
            "description": "Network connection detected from the host.",
            "detection_tip": "Flag uncommon outbound ports or connections to rare countries.",
            "mitre_id": "T1043",
            "mitre_technique": "Commonly Used Port"
        },
        "7": {
            "description": "Image (DLL) loaded into a process.",
            "detection_tip": "Detect unsigned or unusual DLLs in critical processes.",
            "mitre_id": "T1055.001",
            "mitre_technique": "Dynamic-link Library Injection"
        },
        "10": {
            "description": "Process accessed another process.",
            "detection_tip": "Investigate access from low-privileged to SYSTEM-level processes.",
            "mitre_id": "T1055",
            "mitre_technique": "Process Injection"
        },
        "11": {
            "description": "File was created.",
            "detection_tip": "Monitor creation of executables in user directories or temp folders.",
            "mitre_id": "T1105",
            "mitre_technique": "Ingress Tool Transfer"
        },
        "12": {
            "description": "Registry value set.",
            "detection_tip": "Check for autorun keys or persistence paths.",
            "mitre_id": "T1547.001",
            "mitre_technique": "Registry Run Keys / Startup Folder"
        },
        "22": {
            "description": "DNS query recorded.",
            "detection_tip": "Detect DNS tunneling or beaconing to dynamic domains.",
            "mitre_id": "T1071.004",
            "mitre_technique": "Application Layer Protocol: DNS"
        }
    }

    return map.get(event_id, {
        "description": "Unknown or unhandled Sysmon Event ID.",
        "detection_tip": "Refer to official Sysmon documentation.",
        "mitre_id": "-",
        "mitre_technique": "Unknown"
    })
