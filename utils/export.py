import os
import hashlib
import json
from utils.enrich import enrich_ip
from triage.recommend import recommend_response

try:
    from utils.enrich import enrich_virustotal
except ImportError:
    enrich_virustotal = None


def generate_html_report(alerts, output_path):
    html = """
    <html>
    <head>
        <title>SOCscribe Alert Report</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .panel { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px #ccc; margin-bottom: 20px; }
            h2 { color: #003366; }
            h3 { color: #006699; }
            code { background: #eee; padding: 2px 4px; border-radius: 4px; }
            em { color: #666; font-size: 0.9em; }
            details { margin-top: 5px; font-size: 0.9em; }
            summary { cursor: pointer; color: #444; }
        </style>
    </head>
    <body>
        <h1>SOCscribe Alerts Report</h1>
    """

    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    try:
        with open(config_path, "r") as c:
            config = json.load(c)
            abuse_key = config.get("abuseipdb_key")
            vt_key = config.get("virustotal_key")
    except:
        abuse_key = None
        vt_key = None

    for alert in alerts:
        rule = alert.get("rule", {})
        src_ip = alert.get("srcip", "N/A")
        timestamp = alert.get("timestamp", "N/A")
        host = alert.get("agent", {}).get("name", "unknown")
        full_log = alert.get("full_log", "")
        rule_id = str(rule.get("id"))
        description = rule.get("description", "No description")

        ip_data = enrich_ip(src_ip, abuse_key)
        vt_data = {}
        if vt_key and full_log and enrich_virustotal:
            hash_val = hashlib.sha256(full_log.encode()).hexdigest()
            vt_data = enrich_virustotal(hash_val, vt_key)

        html += f"""
        <div class="panel">
            <h2>🚨 Alert ID: {alert.get('id')}</h2>

            <p><strong>Timestamp:</strong> {timestamp}
            <details><summary>What does this mean?</summary>
            <em>The exact time the alert was triggered. Useful for understanding when suspicious activity occurred.</em>
            </details></p>

            <p><strong>Host:</strong> {host}
            <details><summary>What does this mean?</summary>
            <em>This is the endpoint (e.g., computer or server) where the suspicious behavior was detected.</em>
            </details></p>

            <p><strong>Source IP:</strong> {src_ip}
            <details><summary>What does this mean?</summary>
            <em>This is the IP address from which the activity originated — could be an attacker or another host on the network.</em>
            </details></p>

            <p><strong>Description:</strong> {description}
            <details><summary>What does this mean?</summary>
        """

        desc_lower = description.lower()
      
        if "logon success" in desc_lower:
            html += "<em>This means a user successfully logged into the system. If unexpected, it may indicate compromised credentials or lateral movement.</em>"
        elif "logon failure" in desc_lower:
            html += "<em>This indicates a failed login attempt — could signal brute-force, misconfiguration, or unauthorized access attempt.</em>"
        elif "powershell" in desc_lower:
            html += "<em>This indicates that PowerShell was used — commonly abused by attackers to run scripts, malware, or download payloads.</em>"
        elif "cmd" in desc_lower or "command prompt" in desc_lower:
            html += "<em>This suggests use of CMD — attackers often use this to run malicious commands or binaries.</em>"
        elif "wscript" in desc_lower or "cscript" in desc_lower:
            html += "<em>These scripting engines are often used to execute malicious VBS or JS payloads.</em>"
        elif "dropped" in desc_lower or "malware" in desc_lower:
            html += "<em>This alert suggests a suspicious file was written to disk, possibly a malware payload.</em>"
        elif "scheduled" in desc_lower:
            html += "<em>This likely refers to a scheduled task, often used by attackers for persistence or delayed execution.</em>"
        elif "registry" in desc_lower:
            html += "<em>Changes to the Windows registry were detected — this could be related to persistence, privilege escalation, or system tampering.</em>"
        elif "rundll32" in desc_lower:
            html += "<em>Rundll32 is a native Windows binary that can be abused to run malicious DLLs — this could indicate LOLBin usage.</em>"
        elif "network" in desc_lower or "connection" in desc_lower:
            html += "<em>This may indicate outbound communication — monitor for connections to suspicious IPs or C2 servers.</em>"
        elif "mimikatz" in desc_lower:
            html += "<em>Mimikatz was detected — a well-known tool used to extract plaintext credentials and hashes from memory.</em>"
        elif "lsass" in desc_lower:
            html += "<em>Access to LSASS memory was observed — attackers often dump LSASS to retrieve credentials.</em>"
        elif "ransomware" in desc_lower:
            html += "<em>Ransomware behavior was detected — such as file encryption or ransom note creation.</em>"
        elif "remote access" in desc_lower:
            html += "<em>This may indicate a RAT (Remote Access Trojan) or use of remote tools like RDP, AnyDesk, or TeamViewer.</em>"
        elif "service created" in desc_lower:
            html += "<em>New service creation may indicate persistence via Windows services.</em>"
        elif "persistence" in desc_lower:
            html += "<em>This alert suggests a technique to maintain access to the system across reboots or logins.</em>"
        elif "process injection" in desc_lower:
            html += "<em>One process is attempting to inject code into another — often used in stealthy malware attacks.</em>"
        elif "suspicious process" in desc_lower:
            html += "<em>This alert flagged a process that resembles known malicious behavior or anomalies.</em>"
        elif "suspicious parent" in desc_lower:
            html += "<em>A legitimate process is being spawned by an unusual parent — often a red flag for malware execution chains.</em>"
        elif "encoded command" in desc_lower:
            html += "<em>Base64 or obfuscated commands detected — typically used to hide intentions in PowerShell or CMD.</em>"
        elif "obfuscated" in desc_lower:
            html += "<em>Code or command appears intentionally hidden — could be to evade detection.</em>"
        elif "office macro" in desc_lower:
            html += "<em>Malicious macros embedded in Office files are a common infection vector.</em>"
        elif "usb" in desc_lower or "removable" in desc_lower:
            html += "<em>Activity from a USB device was detected — may indicate data exfiltration or initial infection via removable media.</em>"
        elif "vssadmin" in desc_lower:
            html += "<em>VSSAdmin used — often associated with deleting shadow copies during ransomware attacks.</em>"
        elif "schtasks" in desc_lower:
            html += "<em>The ‘schtasks’ utility is used to create or manage scheduled tasks — often abused for persistence.</em>"
        elif "winlogon" in desc_lower:
            html += "<em>Winlogon activity may relate to login behavior or potential persistence mechanisms.</em>"
        elif "taskhostw" in desc_lower:
            html += "<em>Taskhostw.exe was involved — suspicious if used out of context or unexpectedly spawned.</em>"
        elif "wmi" in desc_lower:
            html += "<em>WMI (Windows Management Instrumentation) was used — often leveraged for stealthy remote execution.</em>"
        elif "dll" in desc_lower:
            html += "<em>DLL activity detected — could be legitimate, or could indicate DLL injection or sideloading.</em>"
        elif "mshta" in desc_lower:
            html += "<em>MSHTA was executed — often abused to run malicious HTA (HTML application) payloads.</em>"
        elif "curl" in desc_lower or "wget" in desc_lower:
            html += "<em>Network download tools detected — may be used to fetch payloads from external sources.</em>"
        elif "system32" in desc_lower:
            html += "<em>Execution from system32 directory — monitor if unusual binaries are triggered.</em>"
        elif "temp" in desc_lower:
            html += "<em>Files executed from temporary directories — common in malware staging or unpacking behavior.</em>"
        elif "rclone" in desc_lower:
            html += "<em>Rclone is a legitimate tool used for file sync — but often abused to exfiltrate data.</em>"
        elif "7zip" in desc_lower or "winrar" in desc_lower:
            html += "<em>Archiving tools used — potentially to compress data before exfiltration.</em>"
        elif "sdelete" in desc_lower:
            html += "<em>SDelete securely wipes files — often used to cover tracks or delete forensic evidence.</em>"
        elif "whoami" in desc_lower or "hostname" in desc_lower:
            html += "<em>Recon commands like ‘whoami’ or ‘hostname’ suggest attacker enumeration activity.</em>"
        elif "netstat" in desc_lower or "ipconfig" in desc_lower:
            html += "<em>Network discovery commands — often part of initial attacker recon.</em>"
        elif "net user" in desc_lower or "net localgroup" in desc_lower:
            html += "<em>User enumeration or privilege modification via Net command — watch for abuse.</em>"
        elif "add user" in desc_lower:
            html += "<em>New user account creation — could be legitimate or attacker persistence.</em>"
        elif "bcdedit" in desc_lower:
            html += "<em>BCDEdit modifies boot configuration — watch for attempts to disable protections.</em>"
        elif "defender" in desc_lower:
            html += "<em>Microsoft Defender tampering or status changes detected — could indicate defense evasion.</em>"
        elif "disable" in desc_lower:
            html += "<em>An attempt was made to disable a feature or service — check for signs of tampering.</em>"
        elif "firewall" in desc_lower:
            html += "<em>Firewall configuration was changed — monitor for ports opened for C2 or remote access.</em>"
        elif "rdesktop" in desc_lower or "rdp" in desc_lower:
            html += "<em>Remote Desktop usage — unexpected sessions may signal lateral movement or data theft.</em>"
        elif "explorer.exe" in desc_lower:
            html += "<em>File Explorer spawned unexpectedly — may indicate process masquerading or unusual activity.</em>"
        elif "ntdll.dll" in desc_lower or "kernel32" in desc_lower:
            html += "<em>Low-level Windows DLL interaction — can signal injection or exploit attempts.</em>"
        elif "unsigned" in desc_lower:
            html += "<em>An unsigned binary was executed — potentially malicious or unverified software.</em>"
        elif "encoded" in desc_lower:
            html += "<em>Data or commands appear encoded — used to bypass detection or obfuscate intent.</em>"
        elif "token" in desc_lower:
            html += "<em>Security token manipulation or access — may indicate privilege escalation or impersonation.</em>"
        elif "environment variable" in desc_lower:
            html += "<em>Modifying environment variables — technique used in evasion or payload staging.</em>"
        elif "script block" in desc_lower:
            html += "<em>Script block logging caught suspicious content — may indicate PowerShell-based malware.</em>"
        elif "signed binary" in desc_lower:
            html += "<em>A signed binary was executed — some are abused as LOLBins for stealthy execution.</em>"
        elif "amsi" in desc_lower:
            html += "<em>Attempts to bypass or disable AMSI (Antimalware Scan Interface) — used to hide malicious scripts.</em>"
        else:
            html += "<em>This explains what triggered the alert. Read the message carefully — it may reveal suspicious activity like execution, persistence, or reconnaissance.</em>"

        html += "</details></p>"

        mitre = rule.get("mitre", {})
        tactic_raw = mitre.get("tactic", "Unknown")
        tactic_display = tactic_raw if isinstance(tactic_raw, str) else ", ".join(tactic_raw)
        technique = mitre.get("technique", "")
        technique_id = mitre.get("id", "-")

        if isinstance(technique, list):
            technique = ", ".join(technique)
        technique = technique.strip()

        html += f"""
        <p><strong>MITRE Tactic:</strong> {tactic_display}
        <details><summary>What does this mean?</summary>
        <em>This is the attacker’s goal — for example, execution, privilege escalation, or lateral movement.</em>
        </details></p>

        <p><strong>Technique:</strong> {technique} ({technique_id})
        <details><summary>What does this mean?</summary>
        <em>This describes how the tactic was carried out — such as using PowerShell, command shell, or scheduled tasks.</em>
        </details></p>
        """

        if ip_data.get("geo"):
            geo = ip_data["geo"]
            html += f"<p><strong>Geo Info:</strong> {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}<br/>"
            html += "<details><summary>What does this mean?</summary><em>This shows the suspected physical location and internet provider of the IP address involved.</em></details></p>"

        if ip_data.get("abuse"):
            abuse = ip_data["abuse"]
            html += f"<p><strong>AbuseIPDB:</strong> {abuse.get('abuseConfidenceScore', 0)}/100 | Reports: {abuse.get('totalReports', 0)}<br/>"
            html += "<details><summary>What does this mean?</summary><em>This score reflects how often this IP has been reported as malicious by the community.</em></details></p>"

        if vt_data and "positives" in vt_data:
            html += f"<p><strong>VirusTotal:</strong> {vt_data['positives']} detections | <a href='{vt_data['link']}'>View Report</a><br/>"
            html += "<details><summary>What does this mean?</summary><em>This shows how many antivirus engines flagged the file involved in the alert.</em></details></p>"

        html += "<h3>🎯 Recommended Actions</h3><ul>"
        actions = recommend_response(alert, return_text=True).splitlines()
        for a in actions:
            html += f"<li>{a}</li>"
        html += "</ul>"

        html += "<h3>🧑‍💼 Who Should Investigate This?</h3><p>"
        if isinstance(tactic_raw, list):
            tactic = [t.lower() for t in tactic_raw]
        else:
            tactic = [tactic_raw.lower()]

        if "brute force" in description.lower():
            html += "This can be handled by a <strong>Tier 1 SOC Analyst</strong>.<br/><em>(Likely login abuse or scanning.)</em>"
        elif "persistence" in tactic or "privilege escalation" in tactic:
            html += "This should be escalated to a <strong>Threat Hunter</strong> or <strong>Incident Responder</strong>.<br/><em>(Possible lateral movement or deeper access attempts.)</em>"
        elif technique.lower().startswith("malicious file"):
            html += "A <strong>Malware Analyst</strong> should inspect this file.<br/><em>(Suspicious payload involved.)</em>"
        elif "exfiltration" in tactic:
            html += "Escalate to a <strong>SOC Lead</strong>.<br/><em>(Potential data breach.)</em>"
        else:
            html += "Start with a <strong>Tier 1 SOC Analyst</strong>.<br/><em>Escalate if needed.</em>"

        html += "</p></div>"

    html += "</body></html>"

    with open(output_path, "w") as f:
        f.write(html)
