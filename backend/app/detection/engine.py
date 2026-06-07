import re
import json
import logging
from sqlalchemy.orm import Session
from app.models import Alert, Process, NetworkConnection
from app.intel.client import check_hash_reputation, check_ip_reputation

logger = logging.getLogger("PeszaraDetection")

def analyze_device_telemetry(db: Session, device_id: str, processes: list, network_connections: list) -> list[Alert]:
    """
    Analyzes telemetry logs for a specific device. Runs heuristical rules on processes 
    and network sockets and creates Alert models.
    """
    alerts_to_create = []

    # Heuristic Detection Rules
    for proc in processes:
        cmdline = (proc.get("command_line") or "").lower()
        name = (proc.get("name") or "").lower()
        exe_path = (proc.get("exe_path") or "").lower()
        pid = proc.get("pid")
        sha256 = proc.get("sha256_hash")

        # 1. Threat Intel Check on File Hash
        if sha256:
            reputation, intel_res = check_hash_reputation(db, sha256)
            if reputation == "malicious":
                alerts_to_create.append(Alert(
                    device_id=device_id,
                    title=f"Malicious Executable Hash Blocked: {name}",
                    description=f"Process '{name}' (PID: {pid}) matched a known malicious file hash flagged by threat intelligence. Threat Name: {intel_res.get('threat_name', 'Unknown Malware')}",
                    severity="critical",
                    mitre_tactic="Execution",
                    mitre_technique="T1204.002 (Malicious File)",
                    confidence_score=95,
                    trigger_process_pid=pid,
                    trigger_details={"process": proc, "threat_intel": intel_res}
                ))
            elif reputation == "suspicious":
                alerts_to_create.append(Alert(
                    device_id=device_id,
                    title=f"Suspicious Hash Detected: {name}",
                    description=f"Process '{name}' (PID: {pid}) has a suspicious reputation score on Threat Intel lookup.",
                    severity="medium",
                    mitre_tactic="Execution",
                    mitre_technique="T1204 (User Execution)",
                    confidence_score=70,
                    trigger_process_pid=pid,
                    trigger_details={"process": proc, "threat_intel": intel_res}
                ))

        # 2. Rule: PowerShell Suspicious Switches (Execution T1059.001)
        if "powershell" in name or "powershell" in exe_path:
            suspicious_switches = []
            if "-nop" in cmdline or "-noprofile" in cmdline:
                suspicious_switches.append("NoProfile (-nop)")
            if "-w hidden" in cmdline or "-windowstyle hidden" in cmdline:
                suspicious_switches.append("Hidden Window (-w hidden)")
            if "-enc" in cmdline or "-encodedcommand" in cmdline:
                suspicious_switches.append("Encoded Command (-enc)")
            if "downloadstring" in cmdline or "downloadfile" in cmdline or "http" in cmdline:
                suspicious_switches.append("Web Download Attempt (downloadstring/http)")
            if "iex" in cmdline or "invoke-expression" in cmdline:
                suspicious_switches.append("Inline Execution (iex)")

            if len(suspicious_switches) >= 2:
                alerts_to_create.append(Alert(
                    device_id=device_id,
                    title="Suspicious PowerShell Execution",
                    description=f"PowerShell process (PID: {pid}) launched with suspicious indicators: {', '.join(suspicious_switches)}. Command: {proc.get('command_line')}",
                    severity="high" if "Web Download Attempt" in suspicious_switches or "Encoded Command (-enc)" in suspicious_switches else "medium",
                    mitre_tactic="Execution",
                    mitre_technique="T1059.001 (PowerShell)",
                    confidence_score=85,
                    trigger_process_pid=pid,
                    trigger_details={"process": proc, "triggers": suspicious_switches}
                ))

        # 3. Rule: Mimikatz / Credential Access Heuristics (Credential Access T1003)
        mimikatz_keywords = ["mimikatz", "sekurlsa", "lsadump", "logonpasswords", "wdigest", "tspkg"]
        if any(keyword in cmdline for keyword in mimikatz_keywords):
            alerts_to_create.append(Alert(
                device_id=device_id,
                title="Credential Dumping Activity Detected",
                description=f"Process command line matches keywords associated with Mimikatz credential dumping tools. Command: {proc.get('command_line')}",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001 (LSASS Memory)",
                confidence_score=98,
                trigger_process_pid=pid,
                trigger_details={"process": proc}
            ))

        # 4. Rule: Local Privilege Enumeration / Discovery (Discovery T1033)
        discovery_cmds = ["whoami /priv", "whoami /groups", "net localgroup administrators", "net user /domain"]
        if any(cmd in cmdline for cmd in discovery_cmds):
            alerts_to_create.append(Alert(
                device_id=device_id,
                title="System Privilege Enumeration",
                description=f"Process '{name}' (PID: {pid}) executed an enumeration command indicating reconnaissance post-exploit. Command: {proc.get('command_line')}",
                severity="low",
                mitre_tactic="Discovery",
                mitre_technique="T1033 (System Owner/User Discovery)",
                confidence_score=60,
                trigger_process_pid=pid,
                trigger_details={"process": proc}
            ))

        # 5. Rule: Scheduled Task Registry Persistence (Persistence T1053)
        if "schtasks" in name or "schtasks.exe" in name:
            if "/create" in cmdline:
                alerts_to_create.append(Alert(
                    device_id=device_id,
                    title="Persistence Created via Scheduled Task",
                    description=f"Process spawned schtasks.exe to register a scheduled task. Command: {proc.get('command_line')}",
                    severity="medium",
                    mitre_tactic="Persistence",
                    mitre_technique="T1053.005 (Scheduled Task)",
                    confidence_score=80,
                    trigger_process_pid=pid,
                    trigger_details={"process": proc}
                ))

        # 6. Rule: Service Creation Persistence (Persistence T1543.003)
        if name == "sc.exe" or name == "sc":
            if "create" in cmdline or "config" in cmdline:
                alerts_to_create.append(Alert(
                    device_id=device_id,
                    title="New System Service Registered",
                    description=f"SC utility called to create or configure a system service. Command: {proc.get('command_line')}",
                    severity="high" if "binpath" in cmdline else "medium",
                    mitre_tactic="Persistence",
                    mitre_technique="T1543.003 (Windows Service)",
                    confidence_score=75,
                    trigger_process_pid=pid,
                    trigger_details={"process": proc}
                ))

    # Network Connection Detections
    for conn in network_connections:
        remote_ip = conn.get("remote_address")
        remote_port = conn.get("remote_port")
        pid = conn.get("pid")

        if not remote_ip or remote_ip in ("0.0.0.0", "127.0.0.1"):
            continue

        # 1. Threat Intel Check on Remote IP
        reputation, intel_res = check_ip_reputation(db, remote_ip)
        if reputation == "malicious":
            alerts_to_create.append(Alert(
                device_id=device_id,
                title=f"Connection to Malicious IP: {remote_ip}",
                description=f"A local process (PID: {pid}) initiated a network connection to {remote_ip} which is flagged as malicious by AbuseIPDB (Confidence: {intel_res.get('abuseConfidenceScore', 0)}%).",
                severity="high",
                mitre_tactic="Command and Control",
                mitre_technique="T1071 (Application Layer Protocol)",
                confidence_score=90,
                trigger_process_pid=pid,
                trigger_details={"connection": conn, "threat_intel": intel_res}
            ))

        # 2. Metasploit Default Handler Port / Reverse Shell Port
        if remote_port in (4444, 5555, 6667, 7777):
            alerts_to_create.append(Alert(
                device_id=device_id,
                title=f"Suspicious Port Connection Attempt: {remote_port}",
                description=f"Process (PID: {pid}) connected to remote IP {remote_ip} on port {remote_port}, which is commonly used by hacking frameworks (Metasploit/Netcat) or IRC command bots.",
                severity="high",
                mitre_tactic="Command and Control",
                mitre_technique="T1095 (Non-Application Layer Protocol)",
                confidence_score=85,
                trigger_process_pid=pid,
                trigger_details={"connection": conn}
            ))

    return alerts_to_create


def calculate_risk_score(alerts: list[Alert]) -> int:
    """
    Calculates a dynamic device risk score (0-100) based on active alerts and their severities.
    """
    if not alerts:
        return 0

    weight_map = {
        "low": 10,
        "medium": 25,
        "high": 50,
        "critical": 90
    }

    total_weight = 0
    max_severity = 0
    
    for alert in alerts:
        if alert.resolved:
            continue
        weight = weight_map.get(alert.severity.lower(), 10)
        total_weight += weight
        max_severity = max(max_severity, weight)

    # Risk score calculation: base of maximum single threat + scaling factor for multiple threats
    # Example: If there's 1 high alert (50), risk is at least 50. If there are 3, it caps out higher.
    score = max_severity + int(total_weight * 0.1)
    
    # Cap at 100
    return min(score, 100)
