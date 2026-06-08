from sqlalchemy.orm import Session
from .models import Alert, Device
from .schemas import TelemetryIngest
from .threat_intel import check_ip_reputation, check_hash_reputation
import re

# Simple signature matching lists
SUSPICIOUS_SHELL_ARGS = [
    r"(?i)-encodedcommand",
    r"(?i)downloadstring",
    r"(?i)bypass",
    r"(?i)-nop",
    r"(?i)-w\s+hidden",
    r"(?i)curl\s+",
    r"(?i)wget\s+",
    r"(?i)http[s]?://",
    r"(?i)iwr\s+",
    r"(?i)iex\s+"
]

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe": ("Credential Access", "T1003", "OS Credential Dumping", "CRITICAL"),
    "mimikatz": ("Credential Access", "T1003", "OS Credential Dumping", "CRITICAL"),
    "nc.exe": ("Command and Control", "T1090", "Non-Standard Port", "HIGH"),
    "nc": ("Command and Control", "T1090", "Non-Standard Port", "HIGH"),
    "netcat": ("Command and Control", "T1090", "Non-Standard Port", "HIGH"),
    "procdump.exe": ("Credential Access", "T1003", "OS Credential Dumping", "HIGH"),
    "whoami.exe": ("Discovery", "T1033", "System Owner/User Discovery", "LOW"),
    "whoami": ("Discovery", "T1033", "System Owner/User Discovery", "LOW"),
    "nmap": ("Discovery", "T1046", "Network Service Discovery", "MEDIUM"),
}

PERSISTENCE_PATHS = [
    r"(?i)software\\microsoft\\windows\\currentversion\\run",
    r"(?i)software\\microsoft\\windows\\currentversion\\runonce",
    r"(?i)/etc/cron",
    r"(?i)/etc/rc\.local",
    r"(?i)\.bashrc",
    r"(?i)launchagents",
    r"(?i)launchdaemons"
]

def run_rules_engine(db: Session, device_id: str, telemetry: TelemetryIngest):
    """
    Evaluates ingested telemetry against static heuristic rules and threat intelligence.
    Generates Alerts and updates the Device's overall risk score.
    """
    alerts_created = []

    # 1. PROCESS RULES
    for proc in telemetry.processes:
        proc_name_lower = proc.name.lower()
        cmdline = proc.cmdline or ""
        cmdline_lower = cmdline.lower()

        # Rule 1A: Specific known malicious processes
        if proc_name_lower in SUSPICIOUS_PROCESS_NAMES:
            tactic, technique, desc, severity = SUSPICIOUS_PROCESS_NAMES[proc_name_lower]
            alert = Alert(
                device_id=device_id,
                title=f"Suspicious Utility Executed: {proc.name}",
                description=f"Process '{proc.name}' was executed by user '{proc.username or 'unknown'}'. Cmd: {cmdline}",
                severity=severity,
                mitre_tactic=tactic,
                mitre_technique=technique,
                status="UNRESOLVED"
            )
            db.add(alert)
            alerts_created.append(alert)
            continue

        # Rule 1B: Shell execution with suspicious arguments (T1059 - Command and Scripting Interpreter)
        is_shell = any(sh in proc_name_lower for sh in ["cmd.exe", "powershell.exe", "pwsh", "bash", "sh", "zsh"])
        if is_shell:
            matched_args = [arg for arg in SUSPICIOUS_SHELL_ARGS if re.search(arg, cmdline_lower)]
            if matched_args:
                alert = Alert(
                    device_id=device_id,
                    title=f"Suspicious Shell Activity: {proc.name}",
                    description=f"Process '{proc.name}' was executed with suspicious flags/arguments: '{', '.join(matched_args)}'. Cmdline: '{cmdline}'",
                    severity="HIGH",
                    mitre_tactic="Execution",
                    mitre_technique="T1059",
                    status="UNRESOLVED"
                )
                db.add(alert)
                alerts_created.append(alert)
                continue

        # Rule 1C: Process hash check (VirusTotal threat intel lookup)
        if proc.sha256:
            vt_result = check_hash_reputation(proc.sha256)
            if vt_result.get("malicious", 0) > 0:
                alert = Alert(
                    device_id=device_id,
                    title=f"Malicious Process Hash Detected",
                    description=f"Process '{proc.name}' hash matches a known threat in VirusTotal database. Malicious detections: {vt_result['malicious']}/{vt_result['total']}. SHA256: {proc.sha256}",
                    severity="CRITICAL",
                    mitre_tactic="Execution",
                    mitre_technique="T1204",
                    status="UNRESOLVED"
                )
                db.add(alert)
                alerts_created.append(alert)

    # 2. NETWORK CONNECTION RULES
    for conn in telemetry.connections:
        raddr = conn.raddr or ""
        if not raddr:
            continue

        # Parse remote IP (Format is usually IP:Port)
        ip_parts = raddr.split(":")
        remote_ip = ip_parts[0]

        # Skip local/loopback IPs
        if remote_ip in ["127.0.0.1", "0.0.0.0", "localhost", "::1", "::"] or remote_ip.startswith("192.168.") or remote_ip.startswith("10."):
            continue

        # Rule 2A: Remote IP reputation lookup
        intel_result = check_ip_reputation(remote_ip)
        if intel_result.get("abuse_score", 0) > 20: # Over 20% abuse report rating
            alert = Alert(
                device_id=device_id,
                title="Suspicious Outbound Network Connection",
                description=f"Process '{conn.process_name or 'unknown'}' (PID {conn.pid}) established a socket connection to a high-abuse IP {remote_ip}. AbuseIPDB Score: {intel_result['abuse_score']}%",
                severity="HIGH" if intel_result["abuse_score"] > 50 else "MEDIUM",
                mitre_tactic="Command and Control",
                mitre_technique="T1071",
                status="UNRESOLVED"
            )
            db.add(alert)
            alerts_created.append(alert)

    # 3. FILE ACTIVITY RULES
    for fe in telemetry.file_events:
        filepath = fe.filepath
        filepath_lower = filepath.lower()

        # Rule 3A: Modification of autostart persistence directories
        if any(re.search(p, filepath_lower) for p in PERSISTENCE_PATHS):
            alert = Alert(
                device_id=device_id,
                title="Endpoint Persistence Modification",
                description=f"File activity ({fe.action}) detected on autostart configuration path: {filepath}",
                severity="MEDIUM",
                mitre_tactic="Persistence",
                mitre_technique="T1547",
                status="UNRESOLVED"
            )
            db.add(alert)
            alerts_created.append(alert)

        # Rule 3B: Ransomware detection (e.g. writing locked files or mass crypto rename)
        if filepath_lower.endswith((".locked", ".crypto", ".enc", ".ransom")):
            alert = Alert(
                device_id=device_id,
                title="Potential Ransomware Encryption Detected",
                description=f"File modification on endpoint matching ransomware-related file extension: {filepath}",
                severity="CRITICAL",
                mitre_tactic="Impact",
                mitre_technique="T1486",
                status="UNRESOLVED"
            )
            db.add(alert)
            alerts_created.append(alert)

    # Flush alerts
    if alerts_created:
        db.commit()

    # Recalculate Risk Score
    recalculate_device_risk(db, device_id)

def recalculate_device_risk(db: Session, device_id: str):
    """
    Calculates device risk score based on unresolved alerts.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        return

    unresolved_alerts = db.query(Alert).filter(Alert.device_id == device_id, Alert.status == "UNRESOLVED").all()
    
    score = 0.0
    for alert in unresolved_alerts:
        sev = alert.severity.upper()
        if sev == "LOW":
            score += 10
        elif sev == "MEDIUM":
            score += 25
        elif sev == "HIGH":
            score += 50
        elif sev == "CRITICAL":
            score += 80

    device.risk_score = min(score, 100.0)
    db.commit()
