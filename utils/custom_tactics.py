custom_tactics = {
    "T1003": {
        "title": "T1003 – OS Credential Dumping",
        "what": [
            "Attacker tried to extract passwords or hashes (e.g., from LSASS)",
            "Look for mimikatz, procdump, comsvcs.dll, or LSASS access",
            "Correlate with process access and memory dump attempts"
        ],
        "where": [
            "Sysmon Event ID 10 (Process Access)",
            "Windows Event ID 4656 (Handle request)",
            "Wazuh: mimikatz/YARA/rule triggers"
        ]
    },
    "T1005": {
        "title": "T1005 – Data from Local System",
        "what": [
            "Files were accessed or staged for exfiltration",
            "Watch for archive creation, USB transfers, or access to document folders",
            "Check for compression tools or suspicious file extensions"
        ],
        "where": [
            "Sysmon Event ID 11 (File Create)",
            "Windows file access logs",
            "Wazuh file monitoring rules"
        ]
    },
    "T1012": {
        "title": "T1012 – Query Registry",
        "what": [
            "Attacker queried the registry to discover system settings",
            "Watch for reg.exe queries, PowerShell Get-ItemProperty",
            "Review who ran it and what keys were accessed"
        ],
        "where": [
            "Sysmon ID 1 and 13",
            "Wazuh commandLine analysis",
            "Windows registry access logs"
        ]
    },
    "T1016": {
        "title": "T1016 – System Network Configuration Discovery",
        "what": [
            "Attacker enumerated IP config, routes, DNS, or adapter info",
            "Look for use of ipconfig, netsh, PowerShell Get-NetAdapter",
            "Often precedes lateral movement"
        ],
        "where": [
            "Sysmon Event ID 1 (Command Line usage)",
            "Wazuh: script/command matching for enumeration",
            "PowerShell transcript logs"
        ]
    },
    "T1021": {
        "title": "T1021 – Remote Services",
        "what": [
            "Attacker accessed a system via SMB, RDP, or SSH",
            "Look for interactive logons from new or unexpected IP addresses",
            "Cross-check account used and whether the host is in normal access scope"
        ],
        "where": [
            "Windows Event ID 4624/4625 (Logon Success/Fail)",
            "Sysmon Event ID 3 (Network Connection)",
            "Wazuh: remote access detection rules (RDP/SSH)"
        ]
    },
    "T1021.001": {
        "title": "T1021.001 – Remote Desktop Protocol",
        "what": [
            "RDP used for remote access or lateral movement",
            "Look for odd login times, high session duration, or new RDP sources",
            "Investigate post-login activity (processes, files accessed)"
        ],
        "where": [
            "Windows Event ID 4624 (Logon Type 10)",
            "Sysmon Event ID 3 (Network Connection)",
            "Wazuh: RDP session monitoring"
        ]
    },
    "T1021.002": {
        "title": "T1021.002 – SMB/Windows Admin Shares",
        "what": [
            "Admin shares (C$, IPC$, ADMIN$) accessed for lateral movement or file drops",
            "Look for file copy followed by execution",
            "Track write operations from attacker-controlled IPs"
        ],
        "where": [
            "Windows Event ID 5140 (Shared access)",
            "Sysmon Event ID 11 (File Create)",
            "Wazuh: SMB access alerts"
        ]
    },
    "T1027": {
        "title": "T1027 – Obfuscated Files or Information",
        "what": [
            "Script or payload was encoded (e.g., Base64, XOR)",
            "Detect -EncodedCommand, hex/Unicode encoding, or junk code insertion",
            "Often used to evade detection by AV/EDR"
        ],
        "where": [
            "Sysmon Event ID 1",
            "Wazuh: encoded command pattern match",
            "Windows PowerShell logs (4104)"
        ]
    },
    "T1033": {
        "title": "T1033 – System Owner/User Discovery",
        "what": [
            "Attacker ran whoami, $env:USERNAME, net user to learn about logged-in users",
            "Helps attacker plan privilege escalation or lateral movement"
        ],
        "where": [
            "Sysmon ID 1",
            "Wazuh: commandLine tracking",
            "Windows Event Logs: Logon sessions, user queries"
        ]
    },
    "T1046": {
        "title": "T1046 – Network Service Scanning",
        "what": [
            "Attacker scanned ports/services across internal network",
            "Look for nmap, netstat, or PowerShell-based scanners"
        ],
        "where": [
            "Sysmon Event ID 3",
            "Firewall IDS alerts",
            "Wazuh port scan detection"
        ]
    },
    "T1047": {
        "title": "T1047 – Windows Management Instrumentation",
        "what": [
            "WMI used for remote command or local recon",
            "Review child processes spawned by WmiPrvSE.exe",
            "Trace to lateral movement or recon scripts"
        ],
        "where": [
            "Sysmon Event ID 1 and 3",
            "Windows Event ID 4688",
            "Wazuh WMI tracking rules"
        ]
    },

        "T1050": {
        "title": "T1050 – New Service",
        "what": [
            "New service registered to auto-start malware",
            "Check for unknown or renamed services",
            "Confirm digital signature of service binary"
        ],
        "where": [
            "Windows Event ID 7045",
            "Sysmon Event ID 1",
            "Wazuh: service creation monitoring"
        ]
    },
    "T1053.005": {
        "title": "T1053.005 – Scheduled Task (Windows)",
        "what": [
            "Adversary created/modified a scheduled task to execute a payload",
            "Inspect task names, triggers, and binary paths",
            "Review system startup task behavior for persistence"
        ],
        "where": [
            "Windows Event ID 4698 (Scheduled task created)",
            "Sysmon Event ID 1 (Task launching payload)",
            "Wazuh: task creation audits"
        ]
    },
    "T1055": {
        "title": "T1055 – Process Injection",
        "what": [
            "Check for code injection into remote or system processes",
            "Detect hollowing, APC injection, or thread hijacking",
            "Inspect memory segments, permissions, and injected code size"
        ],
        "where": [
            "Sysmon Event ID 10 (Process Access)",
            "Event ID 1 (for suspicious process creation)",
            "Wazuh: memory analysis or anti-malware logs"
        ]
    },
    "T1056": {
        "title": "T1056 – Input Capture",
        "what": [
            "Keylogging or credential harvesting from user input",
            "Look for injected DLLs, usermode hooks, or WinAPI abuse",
            "May target browsers, RDP, or input-rich apps"
        ],
        "where": [
            "Sysmon Event ID 7 (Image Load)",
            "Sysmon Event ID 1 (Process Create)",
            "Wazuh EDR logs and suspicious DLL alerts"
        ]
    },
    "T1057": {
        "title": "T1057 – Process Discovery",
        "what": [
            "Attacker enumerated running processes to identify security tools or services",
            "Tools: tasklist, ps, Get-Process",
            "Helps adversaries target specific processes for injection or evasion"
        ],
        "where": [
            "Sysmon Event ID 1",
            "Wazuh: command-line parser",
            "PowerShell logs"
        ]
    },
    "T1058": {
        "title": "T1058 – Registry Permission Abuse",
        "what": [
            "Registry keys with weak permissions were overwritten",
            "Target keys include service ImagePath or Run entries"
        ],
        "where": [
            "Sysmon Event ID 13 (Registry Value Set)",
            "Wazuh: registry audit logs",
            "Autoruns and policy comparisons"
        ]
    },
    "T1059": {
        "title": "T1059 – Command and Scripting Interpreter",
        "what": [
            "Adversary used shell or script to run commands (bash, cmd, PowerShell)",
            "Watch for suspicious chaining, encoding, or child process spawns",
            "Detect common binaries used for scripting"
        ],
        "where": [
            "Sysmon Event ID 1",
            "Wazuh: command execution rules",
            "Windows: Event ID 4688"
        ]
    },
    "T1059.001": {
        "title": "T1059.001 – PowerShell",
        "what": [
            "PowerShell process was spawned, likely with -EncodedCommand",
            "Check for base64-encoded payloads and decode them",
            "Trace the parent-child execution chain",
            "Flag unusual paths, hidden arguments, or obfuscated content"
        ],
        "where": [
            "Sysmon Event ID 1 (Process Create)",
            "Wazuh: data.win.eventdata.commandLine",
            "Event logs with script block logging enabled"
        ]
    },
    "T1069": {
        "title": "T1069 – Permission Groups Discovery",
        "what": [
            "Attacker queried AD groups or local admin group membership",
            "Tools: net group, net localgroup, PowerShell Get-ADGroupMember",
            "Used to identify privileged accounts for escalation"
        ],
        "where": [
            "Sysmon Event ID 1",
            "Windows Security logs",
            "Wazuh domain enumeration alerts"
        ]
    },
    "T1070": {
        "title": "T1070 – Indicator Removal on Host",
        "what": [
            "Attacker deleted logs or files to cover tracks",
            "Look for use of wevtutil, Clear-EventLog, rm, or del",
            "Check for gaps in logs or reset timestamps"
        ],
        "where": [
            "Sysmon Event ID 23 (File delete)",
            "Windows Event ID 1102 (Security log cleared)",
            "Wazuh log integrity alerts"
        ]
    },
    "T1071": {
        "title": "T1071 – Application Layer Protocol",
        "what": [
            "C2 or data transfer via HTTP, DNS, SMTP, or other standard protocols",
            "Look for odd domains, beacons, or encoded payloads"
        ],
        "where": [
            "Sysmon Event ID 3 (network connection)",
            "Proxy/Firewall logs",
            "Wazuh DNS and HTTP traffic analysis"
        ]
    },
    "T1078": {
        "title": "T1078 – Valid Accounts",
        "what": [
            "Attacker used stolen or default credentials",
            "Look for abnormal logon patterns or new device logins",
            "Correlate account activity with baseline"
        ],
        "where": [
            "Windows Event ID 4624",
            "Wazuh: user behavior analysis",
            "Sysmon login traces"
        ]
    },
        "T1083": {
        "title": "T1083 – File and Directory Discovery",
        "what": [
            "Attacker scanned the file system to find valuable data",
            "Look for commands like dir, ls, Get-ChildItem, or explorer-based recon",
            "Review access to sensitive folders like C:\\Users, /etc/passwd, or /home"
        ],
        "where": [
            "Sysmon Event ID 1 (Process Create)",
            "Wazuh: commandLine logging",
            "Windows Event ID 4688 (process execution)"
        ]
    },
    "T1105": {
        "title": "T1105 – Ingress Tool Transfer",
        "what": [
            "Tools like certutil, curl, or bitsadmin used to pull second-stage payloads",
            "Detect file downloads from internet-facing domains"
        ],
        "where": [
            "Sysmon Event ID 1",
            "Wazuh: downloader command signatures",
            "Firewall/proxy logs"
        ]
    },
    "T1110": {
        "title": "T1110 – Brute Force",
        "what": [
            "Repeated login attempts using various passwords",
            "Look for failed logons over short period from same source IP",
            "Investigate if followed by a successful login"
        ],
        "where": [
            "Windows Event ID 4625 (failed login), 4624 (success)",
            "Wazuh authentication logs",
            "Firewall logs (source IP correlation)"
        ]
    },
    "T1112": {
        "title": "T1112 – Modify Registry",
        "what": [
            "Attacker altered registry keys for persistence or evasion",
            "Look for suspicious changes to Run/RunOnce, policies, or config keys",
            "Correlate changes with processes or users"
        ],
        "where": [
            "Sysmon Event ID 13 (Registry Value Set)",
            "Wazuh registry audit rules",
            "Windows Event ID 4657"
        ]
    },
    "T1136": {
        "title": "T1136 – Create Account",
        "what": [
            "New user or domain account created (possibly backdoor access)",
            "Check account naming, privilege level, and time of creation",
            "Cross-check with known provisioning systems"
        ],
        "where": [
            "Windows Event ID 4720 (User Created)",
            "Sysmon Event ID 1 (if associated process is malicious)",
            "Wazuh: user creation alerting rules"
        ]
    },
    "T1140": {
        "title": "T1140 – Deobfuscate/Decode Files or Information",
        "what": [
            "Encrypted or packed code was unpacked at runtime",
            "Look for scripts decoding blobs or loading dynamic content",
            "Common before execution of second-stage payloads"
        ],
        "where": [
            "Sysmon Event ID 7 (DLL load)",
            "Sysmon ID 1 (payload runner)",
            "Wazuh: memory decode activity and Base64"
        ]
    },
    "T1203": {
        "title": "T1203 – Exploitation for Client Execution",
        "what": [
            "Software vulnerabilities were exploited to run attacker code",
            "Look for office macros, PDF exploits, or browser exploits",
            "Check who opened the file or visited the site"
        ],
        "where": [
            "AV/EDR exploit logs",
            "Sysmon ID 1 and crash events",
            "Wazuh exploit detection rules"
        ]
    },
    "T1204": {
        "title": "T1204 – User Execution",
        "what": [
            "User triggered execution by clicking a file, link, or script",
            "Common with phishing (email attachment, drive-by download)",
            "Investigate user actions and social engineering lure"
        ],
        "where": [
            "Sysmon Event ID 1 (Process Create)",
            "Wazuh: script execution or macro detection",
            "Email gateway logs (attachment or link tracking)"
        ]
    },
    "T1218": {
        "title": "T1218 – Signed Binary Proxy Execution",
        "what": [
            "Check for use of legit signed tools to launch malware",
            "Inspect mshta.exe, regsvr32.exe, rundll32.exe usage",
            "Look for suspicious command-line arguments or dropped files"
        ],
        "where": [
            "Sysmon Event ID 1 (Process Create)",
            "Windows: Event ID 4688 (new process)",
            "Wazuh: commandLine logs with known proxy binaries"
        ]
    },
    "T1219": {
        "title": "T1219 – Remote Access Software",
        "what": [
            "Attacker installed or used remote tools (TeamViewer, AnyDesk, etc.)",
            "Check for new binaries or auto-start entries",
            "Correlate with user session and network logs"
        ],
        "where": [
            "Sysmon Event ID 1",
            "Wazuh: software install monitoring",
            "Network traffic analysis"
        ]
    },
    "T1497": {
        "title": "T1497 – Virtualization/Sandbox Evasion",
        "what": [
            "Malware checked if running in a VM, sandbox, or debug environment",
            "Look for registry, WMI, or MAC checks",
            "Also watch for timing-based evasion or user-interaction tests"
        ],
        "where": [
            "Sysmon Event ID 1 (sandbox check process)",
            "Registry queries (Sysmon ID 13)",
            "Wazuh sandbox detection rules"
        ]
    },
    "T1543": {
        "title": "T1543 – Create or Modify System Process",
        "what": [
            "System-level services were added or changed to run malware",
            "Review binary path and permissions",
            "Often used for privilege escalation or persistence"
        ],
        "where": [
            "Windows Event ID 7045 (New service installed)",
            "Sysmon ID 1 and 6 (Process and driver load)",
            "Wazuh: service monitoring alerts"
        ]
    },
    "T1546": {
        "title": "T1546 – Event Triggered Execution",
        "what": [
            "Payload set to run on event (logon, startup, scheduled)",
            "Look for strange logon scripts, WMI subscriptions, or task triggers",
            "Check who registered the trigger and for what binary"
        ],
        "where": [
            "Windows Event IDs 4702, 7045",
            "Sysmon Event ID 1 (Process Create)",
            "Wazuh registry/startup script audits"
        ]
    },
    "T1562": {
        "title": "T1562 – Impair Defenses",
        "what": [
            "AV, Defender, or EDR was disabled, bypassed, or excluded",
            "Look for Defender exclusions, tampering with registry or services",
            "Detect dropped DLLs or renamed AV components"
        ],
        "where": [
            "Windows Event IDs 5001, 1116 (Defender status)",
            "Sysmon Event ID 1 (tampering process)",
            "Wazuh: EDR/AV integrity checks and audit logs"
        ]
    },
    "T1566.001": {
        "title": "T1566.001 – Spearphishing Attachment",
        "what": [
            "User opened an attachment from email",
            "Check filename and content of attachment",
            "Correlate with user mailbox and delivery logs",
            "Trace if any macro or executable was launched"
        ],
        "where": [
            "Email gateway logs",
            "Sysmon Event ID 11 (File Create)",
            "Process chain from Outlook or email client"
        ]
    }
}



    

