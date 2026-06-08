from openai import OpenAI
from .config import OPENAI_API_KEY
from typing import List
from .models import Alert

def analyze_incident_with_ai(device_info: dict, alerts: List[Alert]) -> dict:
    """
    Analyzes endpoint telemetry and alerts. Uses OpenAI if key is present,
    otherwise uses a smart local template generator to detail the attack chain.
    """
    if not alerts:
        return {
            "summary": "No active alerts detected on this endpoint. The device appears healthy.",
            "analysis": "The agent telemetry reports normal execution flow. No indicators of compromise (IoC) are active.",
            "remediation": "1. Keep system software and security agent updated.\n2. Periodically audit user login times and remote connections."
        }

    # Format alerts for the prompt / local analyzer
    alert_list_str = ""
    has_ransomware = False
    has_credentials = False
    has_shell = False
    has_network = False
    has_persistence = False

    for idx, alert in enumerate(alerts):
        alert_list_str += f"- Alert {idx+1}: {alert.title} (Severity: {alert.severity}, MITRE Tactic: {alert.mitre_tactic or 'None'}, Technique: {alert.mitre_technique or 'None'})\n  Description: {alert.description}\n\n"
        
        tactic = (alert.mitre_tactic or "").lower()
        title = alert.title.lower()
        if "ransomware" in title or "impact" in tactic:
            has_ransomware = True
        if "credential" in tactic or "mimikatz" in title:
            has_credentials = True
        if "shell" in title or "execution" in tactic:
            has_shell = True
        if "network" in title or "socket" in title or "command" in tactic:
            has_network = True
        if "persistence" in tactic:
            has_persistence = True

    # If OpenAI Key is available, query OpenAI
    if OPENAI_API_KEY:
        try:
            client = OpenAI(api_key=OPENAI_API_KEY)
            prompt = f"""
You are a Principal Incident Response Architect. Analyze the following security incidents on an endpoint device.

=== DEVICE DETAILS ===
Hostname: {device_info.get('hostname')}
OS: {device_info.get('os_name')} ({device_info.get('os_version')})
IP Address: {device_info.get('ip_address')}
User: {device_info.get('logged_in_user')}
Current Risk Score: {device_info.get('risk_score')}/100

=== ACTIVE INCIDENTS & ALERTS ===
{alert_list_str}

Please generate a professional Incident Response report:
1. **Summary**: A concise, non-technical explanation of the active threats on this device.
2. **Analysis (Attack Chain)**: Detailed chronological analysis mapping how these alerts might form an attack chain (e.g., initial execution -> credential access -> command and control).
3. **Remediation**: Bulleted list of actionable next steps for a SOC analyst to mitigate these threats immediately.

Return your response in a clear JSON structure with keys: "summary", "analysis", "remediation" (all formatted in clean Markdown).
Do not output anything other than raw valid JSON.
"""
            chat_completion = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a professional cybersecurity incident response copilot. Output JSON only."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            
            import json
            result = json.loads(chat_completion.choices[0].message.content)
            if "summary" in result and "analysis" in result and "remediation" in result:
                return result
        except Exception as e:
            print(f"OpenAI API error: {e}. Falling back to rule-based templated analysis.")

    # Rule-Based smart templated analysis fallback
    summary_parts = []
    analysis_parts = []
    remediation_parts = []

    # Assemble summary based on matching criteria
    if has_ransomware:
        summary_parts.append("Critical threat detected: Indicators of a Ransomware attack executing on the system.")
        remediation_parts.append("1. **IMMEDIATE HOST ISOLATION**: Disconnect the network cable or disable Wi-Fi/NIC immediately to halt lateral movement and further encryption.")
        remediation_parts.append("2. Kill any active processes associated with the file extension modifications.")
    
    if has_credentials:
        summary_parts.append("High-severity threat: Credential extraction tools (like Mimikatz/lsass dumpers) were executed.")
        remediation_parts.append("3. **CREDENTIAL REVOCATION**: Force reset all passwords for accounts logged into this machine, especially privileged domain accounts.")
    
    if has_shell:
        summary_parts.append("Suspicious code execution detected: Command interpreters spawning scripts with hidden/obfuscated parameters.")
        remediation_parts.append("4. Terminate process execution paths that spawned suspicious PowerShell or Cmd.exe trees.")
        
    if has_network:
        summary_parts.append("C2 indicator: Outbound connection established to high-abuse reputation IPs.")
        remediation_parts.append("5. Block remote IP connections at the firewall layer.")

    if has_persistence:
        summary_parts.append("Persistence mechanism configured: Unrecognized writes to boot registries or startup files.")
        remediation_parts.append("6. Clean the startup registry items/cron entries to prevent the malware from surviving restarts.")

    # General descriptions if no specific rules match
    if not summary_parts:
        summary_parts.append("Suspicious activity has been flagged on this endpoint. The risk score has been adjusted accordingly.")

    # Chronological Analysis
    analysis_parts.append(f"### Chronological Attack Tree Analysis")
    analysis_parts.append(f"A threat profile has been established for host **{device_info.get('hostname')}** (Risk Score: **{device_info.get('risk_score')}/100**).")
    
    step = 1
    if has_shell:
        analysis_parts.append(f"{step}. **Phase: Execution** - The attacker executed custom commands/scripts (MITRE T1059) to gain initial footing on the endpoint.")
        step += 1
    if has_persistence:
        analysis_parts.append(f"{step}. **Phase: Persistence** - The system detected attempts to register registry run-keys or boot components (MITRE T1547) to survive reboots.")
        step += 1
    if has_credentials:
        analysis_parts.append(f"{step}. **Phase: Credential Access** - LSASS was targeted or known dumpers (Mimikatz) were run to capture plain text tokens/NTLM hashes (MITRE T1003).")
        step += 1
    if has_network:
        analysis_parts.append(f"{step}. **Phase: Command & Control** - Telemetry records outbound sockets (MITRE T1071) mapping to reported malware beacons or Tor proxies.")
        step += 1
    if has_ransomware:
        analysis_parts.append(f"{step}. **Phase: Impact** - Attacker initiated bulk encryption of user/system files (MITRE T1486), creating `.locked` or `.crypto` artifacts.")
        step += 1

    if len(remediation_parts) == 0:
        remediation_parts.append("1. Isolate device and scan for signatures.")
        remediation_parts.append("2. Audit active processes and examine command-line history.")

    return {
        "summary": " ".join(summary_parts),
        "analysis": "\n\n".join(analysis_parts),
        "remediation": "\n".join(remediation_parts)
    }
