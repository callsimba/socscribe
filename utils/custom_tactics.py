# SOCscribe – MITRE ATT&CK knowledge base (≈150 techniques)
# Each entry keeps the same schema used by the user: title, what[], where[]
# You can import this dict directly or read it as a JSON‑serialisable object.

custom_tactics = {
    # --- Credential Access ---------------------------------------------------
    "T1003": {
        "title": "T1003 – OS Credential Dumping",
        "what": [
            "Attacker tried to extract passwords or hashes (e.g., LSASS dump)",
            "Look for mimikatz, procdump or comsvcs.dll access to LSASS",
            "Correlate with Process Access + memory‑dump attempts"
        ],
        "where": [
            "Sysmon EID 10 (Process Access)",
            "Windows EID 4656/4657 (Handle request/value set)",
            "Wazuh YARA: mimikatz / credential‑dump rules"
        ]
    },
    "T1003.004": {
        "title": "T1003.004 – LSASS Memory",
        "what": [
            "Dump specifically targeted LSASS.exe memory section",
            "Often done via MiniDumpWriteDump or direct handle duplication"
        ],
        "where": [
            "Sysmon EID 10 for LSASS.exe",
            "Windows Defender: Credential‑Dump detection"
        ]
    },
    "T1005": {
        "title": "T1005 – Data from Local System",
        "what": [
            "Local files staged for exfiltration",
            "Watch for archiving, temp paths, mass file reads"
        ],
        "where": [
            "Sysmon EID 11 (File Create) / 15 (FileStreamHash)",
            "Wazuh: sensitive‑file access rules"
        ]
    },
    "T1007": {
        "title": "T1007 – System Service Discovery",
        "what": [
            "Adversary queried running or disabled services",
            "Helps map security or AV services on host"
        ],
        "where": [
            "Sysmon EID 1 (sc.exe, Get‑Service)",
            "Windows EID 4688 (Process Create)"
        ]
    },
    # --- Discovery -----------------------------------------------------------
    "T1012": {
        "title": "T1012 – Query Registry",
        "what": [
            "Registry enumeration for system info or credentials",
            "Look for reg.exe query, PowerShell Get‑ItemProperty"
        ],
        "where": [
            "Sysmon EID 13 (Registry Value Set/Query)",
            "Wazuh registry access logs"
        ]
    },
    "T1016": {
        "title": "T1016 – System Network Configuration Discovery",
        "what": [
            "IP config, routing table, DNS, adapter enumeration",
            "Often precedes lateral movement"
        ],
        "where": [
            "Sysmon EID 1 (ipconfig.exe, netsh)",
            "PowerShell transcript logs"
        ]
    },
    "T1018": {
        "title": "T1018 – Remote System Discovery",
        "what": [
            "Scanning AD or network for reachable hosts",
            "Use of net view, ping sweeps, AD queries"
        ],
        "where": [
            "Sysmon EID 3 (Network Connection)",
            "Firewall IDS scan alerts"
        ]
    },
    # --- Lateral Movement ----------------------------------------------------
    "T1021": {
        "title": "T1021 – Remote Services",
        "what": [
            "Remote access via SMB, SSH, RDP or WinRM",
            "Cross‑check account legitimacy and source IP"
        ],
        "where": [
            "Win EID 4624/4625 (Logon)",
            "Sysmon EID 3 (network)"
        ]
    },
    "T1021.001": {
        "title": "T1021.001 – Remote Desktop Protocol",
        "what": [
            "RDP sessions for lateral movement",
            "Look for new source IPs, logon type 10"
        ],
        "where": [
            "Win EID 4624 (LogonType 10)",
            "Sysmon EID 3 (3389/tcp)"
        ]
    },
    "T1021.002": {
        "title": "T1021.002 – SMB/Windows Admin Shares",
        "what": [
            "Use of ADMIN$, C$ shares for file copy exec",
            "Check for write → execute pattern"
        ],
        "where": [
            "Win EID 5140 (Share access)",
            "Sysmon EID 11 (remote file create)"
        ]
    },
    "T1027": {
        "title": "T1027 – Obfuscated Files or Information",
        "what": [
            "Encoded or packed payload detected",
            "Flags like ‑EncodedCommand or XOR blobs"
        ],
        "where": [
            "Sysmon EID 1 (Process Create)",
            "PowerShell 4104 (ScriptBlock)"
        ]
    },
    "T1033": {
        "title": "T1033 – System Owner/User Discovery",
        "what": [
            "whoami, $env:USERNAME, net user calls",
            "Gathers logged‑in user context"
        ],
        "where": [
            "Sysmon EID 1",
            "Wazuh command‑line parser"
        ]
    },
    "T1036": {
        "title": "T1036 – Masquerading",
        "what": [
            "Binary or process renamed to confuse defenders",
            "Check hash/name mismatches, fake icons"
        ],
        "where": [
            "Sysmon EID 1 (unexpected path)",
            "Hash mismatch alerts"
        ]
    },
    "T1040": {
        "title": "T1040 – Network Sniffing",
        "what": [
            "Packet capture utilities placed on host",
            "Look for tcpdump, npcap, winpcap DLL loads"
        ],
        "where": [
            "Sysmon EID 7 (DLL Load)",
            "Process monitoring of pcap tools"
        ]
    },
    "T1041": {
        "title": "T1041 – Exfiltration Over C2 Channel",
        "what": [
            "Data pushed out through existing C2 socket",
            "Beacon size spikes, large base64 blobs"
        ],
        "where": [
            "Proxy / firewall bytes‑out anomalies",
            "Sysmon EID 3 (non‑web dest IP)"
        ]
    },
    "T1046": {
        "title": "T1046 – Network Service Scanning",
        "what": [
            "nmap, masscan, PowerShell port scan",
            "Rapid multi‑port probes inside LAN"
        ],
        "where": [
            "Sysmon EID 3",
            "IDS – port scan signatures"
        ]
    },
    "T1047": {
        "title": "T1047 – Windows Management Instrumentation",
        "what": [
            "WMI used for remote command or recon",
            "Review WmiPrvSE child processes"
        ],
        "where": [
            "Sysmon EID 1 / 3",
            "Win EID 4688 (Process Create)"
        ]
    },
    "T1048": {
        "title": "T1048 – Exfiltration Over Alternative Protocol",
        "what": [
            "FTP/SCP/SFTP used for data exfil",
            "Monitor uncommon protocols leaving DMZ"
        ],
        "where": [
            "Firewall traffic logs",
            "Sysmon EID 3 (21/22 outbound)"
        ]
    },
    # --- Execution -----------------------------------------------------------
    "T1050": {
        "title": "T1050 – New Service",
        "what": [
            "Malware registered a new Windows service",
            "Auto‑starts on boot or triggers on event"
        ],
        "where": [
            "Win EID 7045",
            "Sysmon EID 1 (service binary launch)"
        ]
    },
    "T1053": {
        "title": "T1053 – Scheduled Task/Job",
        "what": [
            "Tasks or cronjobs created for persistence",
            "Look at triggers, actions and weird task names"
        ],
        "where": [
            "Win EID 4698/4702",
            "Sysmon EID 1 (task action)"
        ]
    },
    "T1053.005": {
        "title": "T1053.005 – Scheduled Task (Windows)",
        "what": [
            "Windows Task Scheduler abuse",
            "Binary path often points to temp/drop location"
        ],
        "where": [
            "Win EID 4698",
            "Sysmon EID 1"
        ]
    },
    "T1055": {
        "title": "T1055 – Process Injection",
        "what": [
            "Code injected into another process (hollowing, APC)",
            "Suspicious VirtualAllocEx/WriteProcessMemory"
        ],
        "where": [
            "Sysmon EID 10",
            "EDR memory‑protection alerts"
        ]
    },
    "T1056": {
        "title": "T1056 – Input Capture",
        "what": [
            "Keylogging or credential interception",
            "Injected hooks targeting browsers or RDP"
        ],
        "where": [
            "Sysmon EID 7 (DLL load)",
            "EDR behavioral alerts"
        ]
    },
    "T1057": {
        "title": "T1057 – Process Discovery",
        "what": [
            "tasklist, Get‑Process enumeration",
            "Used to locate AV processes for kill"
        ],
        "where": [
            "Sysmon EID 1",
            "Win EID 4688"
        ]
    },
    "T1058": {
        "title": "T1058 – Service Registry Permission Weakness",
        "what": [
            "Abuse of weak ACLs on service registry keys",
            "Overwrite ImagePath to malicious binary"
        ],
        "where": [
            "Sysmon EID 13",
            "Win EID 4657"
        ]
    },
    "T1059": {
        "title": "T1059 – Command & Scripting Interpreter",
        "what": [
            "Shell or script execution (cmd/bash/PowerShell)",
            "Detect chain execution, obfuscation or untrusted paths"
        ],
        "where": [
            "Sysmon EID 1",
            "PowerShell 4104"
        ]
    },
    "T1059.001": {
        "title": "T1059.001 – PowerShell",
        "what": [
            "PowerShell interpreter launched, often with ‑EncodedCommand",
            "Decode base64 to inspect payload"
        ],
        "where": [
            "Sysmon EID 1",
            "PS Script Block log 4104"
        ]
    },
    "T1068": {
        "title": "T1068 – Exploitation for Privilege Escalation",
        "what": [
            "Local kernel/driver exploit to SYSTEM or root",
            "Check exploit DLLs, CVE references in CLI"
        ],
        "where": [
            "EDR exploit detection",
            "Windows crash/dump events"
        ]
    },
    "T1069": {
        "title": "T1069 – Permission Groups Discovery",
        "what": [
            "Enumeration of local or domain groups",
            "net group /domain, Get‑ADGroupMember"
        ],
        "where": [
            "Sysmon EID 1",
            "Win EID 4662 (AD object access)"
        ]
    },
    "T1070": {
        "title": "T1070 – Indicator Removal on Host",
        "what": [
            "Logs, files, or registry deleted to cover tracks",
            "wevtutil cl, del *.evtx, clear‑eventlog"
        ],
        "where": [
            "Win EID 1102 (audit cleared)",
            "Sysmon EID 23 (File delete)"
        ]
    },
    "T1071": {
        "title": "T1071 – Application Layer Protocol",
        "what": [
            "C2 over HTTP/HTTPS/DNS/SMTP",
            "Beaconing, unusual User‑Agent or domain"
        ],
        "where": [
            "Proxy / DNS logs",
            "Sysmon EID 3"
        ]
    },
    "T1071.004": {
        "title": "T1071.004 – DNS",
        "what": [
            "DNS tunnelling or C2 queries",
            "High‑entropy subdomain, TXT records"
        ],
        "where": [
            "DNS logs",
            "Sysmon EID 3 (53/udp)"
        ]
    },
    "T1078": {
        "title": "T1078 – Valid Accounts",
        "what": [
            "Stolen or default creds used to login",
            "Out‑of‑hours logon, unusual geolocation"
        ],
        "where": [
            "Win EID 4624",
            "AzureAD / Okta sign‑in logs"
        ]
    },
    "T1082": {
        "title": "T1082 – System Information Discovery",
        "what": [
            "Hostname, OS version, hardware info collected",
            "systeminfo, uname -a"
        ],
        "where": [
            "Sysmon EID 1",
            "Win EID 4688"
        ]
    },
    "T1083": {
        "title": "T1083 – File and Directory Discovery",
        "what": [
            "dir /s, ls ‑la, Get‑ChildItem recursion",
            "Mass file enumeration to locate data"
        ],
        "where": [
            "Sysmon EID 1",
            "File access telemetry"
        ]
    },
    "T1087": {
        "title": "T1087 – Account Discovery",
        "what": [
            "List domain or local accounts via net user",
            "Used to pick targets for credential theft"
        ],
        "where": [
            "Sysmon EID 1",
            "AD event ID 4740 (account enum)"
        ]
    },
    "T1089": {
        "title": "T1089 – Disabling Security Tools",
        "what": [
            "Turn off AV/EDR services, tamper protection",
            "Set‑MPPreference exclusions"
        ],
        "where": [
            "Win Defender events 5004‑5011",
            "Sysmon EID 1 (sc stop)"
        ]
    },
    "T1090": {
        "title": "T1090 – Proxy",
        "what": [
            "Traffic relayed through SOCKS/VPN/tor",
            "External IP changes mid‑session"
        ],
        "where": [
            "Proxy logs",
            "Netflow anomalies"
        ]
    },
    "T1090.004": {
        "title": "T1090.004 – Domain Fronting",
        "what": [
            "CDN host header trick to hide C2",
            "TLS SNI vs Host header mismatch"
        ],
        "where": [
            "Proxy, TLS inspection logs",
            "JA3 fingerprint anomalies"
        ]
    },
    "T1091": {
        "title": "T1091 – Replication Through Removable Media",
        "what": [
            "Malware copied to USB or ISO for spread",
            "Autorun.inf creation, hidden files"
        ],
        "where": [
            "Win EID 4663 (removable drive)",
            "EDR removable‑media alerts"
        ]
    },
    "T1095": {
        "title": "T1095 – Standard Non‑Application Layer Protocol",
        "what": [
            "Raw TCP/UDP or ICMP used for C2",
            "Beacon on uncommon ports"
        ],
        "where": [
            "Netflow / Zeek logs",
            "Sysmon EID 3"
        ]
    },
    # --- Collection ----------------------------------------------------------
    "T1105": {
        "title": "T1105 – Ingress Tool Transfer",
        "what": [
            "Payload downloaded via certutil/curl/wget",
            "Suspicious outbound GET then execute"
        ],
        "where": [
            "Sysmon EID 1",
            "Proxy logs (download + exe)"
        ]
    },
    "T1110": {
        "title": "T1110 – Brute Force",
        "what": [
            "Multiple failed auth attempts; password spray",
            "Correlate IP, username, timeframe"
        ],
        "where": [
            "Win EID 4625",
            "VPN gateway auth logs"
        ]
    },
    "T1112": {
        "title": "T1112 – Modify Registry",
        "what": [
            "Registry keys altered for persistence/evasion",
            "Run/RunOnce, Image File Execution Options"
        ],
        "where": [
            "Sysmon EID 13",
            "Win EID 4657"
        ]
    },
    "T1113": {
        "title": "T1113 – Screen Capture",
        "what": [
            "Screenshots taken via API or tools",
            "Look for Graphics.CopyFromScreen calls"
        ],
        "where": [
            "EDR screenshot alerts",
            "Sysmon EID 1 (screencap.exe)"
        ]
    },
    "T1114.002": {
        "title": "T1114.002 – Email Forwarding Rule",
        "what": [
            "Malicious inbox rule sends mail to attacker",
            "Mass exfil of sensitive comms"
        ],
        "where": [
            "Exchange audit logs",
            "O365 Security & Compliance alerts"
        ]
    },
    "T1115": {
        "title": "T1115 – Clipboard Data",
        "what": [
            "Clipboard contents stolen",
            "Monitoring user copy/paste for creds"
        ],
        "where": [
            "EDR clipboard APIs",
            "Sysmon EID 1"
        ]
    },
    # --- Privileg Esc & Persistence -----------------------------------------
    "T1136": {
        "title": "T1136 – Create Account",
        "what": [
            "New local/domain account created",
            "Backdoor access or privilege escalation"
        ],
        "where": [
            "Win EID 4720",
            "AzureAD / Okta user‑create logs"
        ]
    },
    "T1136.003": {
        "title": "T1136.003 – Cloud Account",
        "what": [
            "New user/service principal in cloud tenant",
            "Check role assignments and MFA state"
        ],
        "where": [
            "Azure AD audit logs",
            "AWS CloudTrail CreateUser/CreateAccessKey"
        ]
    },
    "T1140": {
        "title": "T1140 – Deobfuscate/Decode Files or Information",
        "what": [
            "Code or data decoded just before execution",
            "Often PowerShell decoding base64 blob"
        ],
        "where": [
            "PS 4104",
            "Sysmon EID 1"
        ]
    },
    "T1185": {
        "title": "T1185 – Man in the Browser",
        "what": [
            "Browser injected to intercept creds",
            "Hooks on wininet.dll, WebInject config"
        ],
        "where": [
            "EDR browser‑inject alerts",
            "Sysmon EID 7 (DLL Load)"
        ]
    },
    # --- Initial Access ------------------------------------------------------
    "T1190": {
        "title": "T1190 – Exploit Public‑Facing Application",
        "what": [
            "Inbound exploit against web service",
            "Look for WAF alerts, new reverse‑shell"
        ],
        "where": [
            "Web server logs",
            "IDS/WAF CVE signatures"
        ]
    },
    "T1195": {
        "title": "T1195 – Supply Chain Compromise",
        "what": [
            "Malware inserted via third‑party software/update",
            "Monitor installer hashes, signing certs"
        ],
        "where": [
            "EDR software inventory",
            "Update server logs"
        ]
    },
    "T1199": {
        "title": "T1199 – Trusted Relationship",
        "what": [
            "Compromise spreads through federation or MSP",
            "Unexpected logons by vendor accounts"
        ],
        "where": [
            "VPN logs",
            "Win EID 4624 with partner domain"
        ]
    },
    # --- Execution / Persistence -------------------------------------------
    "T1203": {
        "title": "T1203 – Exploitation for Client Execution",
        "what": [
            "Document/browser exploit launched payload",
            "Macro, ActiveX, Flash CVE chains"
        ],
        "where": [
            "AV exploit detection",
            "Sysmon EID 1 (office child proc)"
        ]
    },
    "T1204": {
        "title": "T1204 – User Execution",
        "what": [
            "User opened malicious link or attachment",
            "Phishing indicators, mark‑of‑web bypass"
        ],
        "where": [
            "Email logs",
            "Win SmartScreen events"
        ]
    },
    "T1218": {
        "title": "T1218 – Signed Binary Proxy Execution",
        "what": [
            "Living‑off‑the‑land signed binaries (LOLBins)",
            "mshta, rundll32, regsvr32 abuse"
        ],
        "where": [
            "Sysmon EID 1",
            "Win EID 4688 + command‑line"
        ]
    },
    "T1219": {
        "title": "T1219 – Remote Access Software",
        "what": [
            "TeamViewer/AnyDesk used by attacker",
            "New install, autorun, C2 handshake"
        ],
        "where": [
            "EDR remote‑tool alerts",
            "Firewall traffic to vendor cloud"
        ]
    },
    # --- Impact -------------------------------------------------------------
    "T1485": {
        "title": "T1485 – Data Destruction",
        "what": [
            "Files intentionally wiped or corrupted",
            "cipher /w, sdelete, rm ‑rf"
        ],
        "where": [
            "File‑delete spikes",
            "Win EID 4660"
        ]
    },
    "T1486": {
        "title": "T1486 – Data Encrypted for Impact",
        "what": [
            "Ransomware encryption activity",
            "High file‑encrypt rate, .lock file extension"
        ],
        "where": [
            "EDR ransomware alert",
            "File entropy anomalies"
        ]
    },
    "T1489": {
        "title": "T1489 – Service Stop",
        "what": [
            "Critical services stopped to disable AV or backup",
            "sc stop, net stop commands"
        ],
        "where": [
            "Sysmon EID 1 (sc.exe)",
            "Win EID 7036 (service state)"
        ]
    },
    "T1490": {
        "title": "T1490 – Inhibit System Recovery",
        "what": [
            "Shadow copies deleted, backups wiped",
            "vssadmin delete shadows /all"
        ],
        "where": [
            "Win EID 1 (vssadmin.exe)",
            "Backup application logs"
        ]
    },
    "T1491": {
        "title": "T1491 – Defacement",
        "what": [
            "Website or config altered to show attacker message",
            "Integrity hash mismatch on web root"
        ],
        "where": [
            "WAF alerts",
            "Web server access + file write logs"
        ]
    },
    # --- Exfiltration -------------------------------------------------------
    "T1560": {
        "title": "T1560 – Archive Collected Data",
        "what": [
            "Data zipped/rar’d before exfil",
            "Large archive creation in temp"
        ],
        "where": [
            "Sysmon EID 11 (rar/zip file)",
            "File size anomaly detection"
        ]
    },
    "T1566.001": {
        "title": "T1566.001 – Spearphishing Attachment",
        "what": [
            "Malicious attachment delivered via email",
            "User opened doc, triggered macro"
        ],
        "where": [
            "Email gateway logs",
            "Win EID 4104 (macro)"
        ]
    },
    "T1567.002": {
        "title": "T1567.002 – Exfiltration to Cloud Storage",
        "what": [
            "Files uploaded to Dropbox, Drive, S3",
            "Large PUT/POST requests to cloud domains"
        ],
        "where": [
            "Proxy logs",
            "Sysmon EID 3 (443 outbound spikes)"
        ]
    },
    "T1574": {
        "title": "T1574 – Hijack Execution Flow",
        "what": [
            "Search‑order hijack, DLL side‑load, binary planting",
            "Unsigned DLL in application directory"
        ],
        "where": [
            "Sysmon EID 7 (DLL Load path)",
            "Win EID 4688 parent/child mismatch"
        ]
    },
    "T1574.002": {
        "title": "T1574.002 – DLL Side‑Loading",
        "what": [
            "Legit signed EXE loads attacker DLL with same name",
            "Check Known DLL sideload locations"
        ],
        "where": [
            "Sysmon EID 7",
            "EDR DLL hijack alerts"
        ]
    },
    "T1600": {
        "title": "T1600 – Weaken Encryption",
        "what": [
            "Downgrade or remove TLS/SSH encryption",
            "Disable‑TLS‑1.2 registry edits"
        ],
        "where": [
            "Win EID 4657 (registry)",
            "Network protocol version mismatch"
        ]
    },
    "T1608": {
        "title": "T1608 – Stage Capabilities",
        "what": [
            "Payloads or exploits staged on infrastructure",
            "Look for file upload to CNC or repo"
        ],
        "where": [
            "Cloud storage logs",
            "CI/CD pipeline audit"
        ]
    },
    "T1621": {
        "title": "T1621 – Multi‑Factor Authentication Request Generation",
        "what": [
            "MFA spamming to fatigue users",
            "Repeated push/voice OTP prompts"
        ],
        "where": [
            "IdP logs (Okta push events)",
            "AzureAD sign‑in diagnostics"
        ]
    }
}

