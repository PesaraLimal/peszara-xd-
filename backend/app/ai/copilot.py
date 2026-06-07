import json
import logging
import httpx
from app.config import settings
from app.models import Alert, Device

logger = logging.getLogger("PeszaraAICopilot")

SYSTEM_PROMPT = """You are a Principal Cybersecurity Incident Responder, DFIR Specialist, and Threat Hunter.
Your task is to analyze endpoint telemetry, alerts, and suspicious events on a specific device, and explain them in clear, actionable security terms.

You must respond ONLY with a JSON object containing the following keys (do not include markdown block formatting, just the raw JSON):
{
  "summary": "Plain-English summary of what this alert means and why it was triggered.",
  "mitre_explanation": "Detailed explanation mapping this behavior to the MITRE ATT&CK framework tactics and techniques.",
  "timeline_explanation": "Chronological reconstruction of how this process fits into a typical attack flow based on the process metadata.",
  "remediation_steps": "Step-by-step instructions for the SOC analyst to contain, eradicate, and recover from this threat.",
  "risk_score_explanation": "An explanation of why this event increases the device risk score and how severe the threat is."
}
"""

def generate_offline_analysis(alert: Alert, device: Device) -> dict:
    """Fallback generator for offline/unconfigured environments."""
    title = alert.title
    tactic = alert.mitre_tactic or "Unknown"
    technique = alert.mitre_technique or "Unknown"
    pid = alert.trigger_process_pid or "Unknown"
    details = alert.trigger_details or {}
    proc_info = details.get("process", {})
    cmdline = proc_info.get("command_line", "N/A")
    
    return {
        "summary": f"This alert ('{title}') was triggered on device '{device.hostname}' due to suspicious behavior associated with process ID {pid}. The system telemetry recorded command line activity: '{cmdline}'. This indicates a potential unauthorized attempt to run systems utility with administrative or bypass switches.",
        "mitre_explanation": f"This threat maps to the MITRE ATT&CK tactic '{tactic}' under technique '{technique}'. Historically, attackers leverage these command lines to evade defenses, establish persistence, or perform system reconnaissance on high-value hosts.",
        "timeline_explanation": f"1. The process was spawned on the host under the user context '{device.logged_in_user}'.\n2. The system telemetry recorded command options matching predefined threat rules.\n3. The backend threat engine calculated a risk increase and registered a {alert.severity.upper()} alert on {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}.",
        "remediation_steps": f"1. Isolate the device '{device.hostname}' from the local network to prevent potential lateral movement.\n2. Terminate the process ID {pid} immediately.\n3. Audit the user account '{device.logged_in_user}' for any anomalous login locations or access spikes.\n4. Run a full endpoint scan using the telemetry agent to confirm if additional threats persist.",
        "risk_score_explanation": f"The device's risk score was adjusted dynamically due to this {alert.severity} severity event. Since it involves {tactic} capabilities, it poses an immediate risk of system compromise if left uncontained."
    }

def investigate_incident(alert: Alert, device: Device) -> dict:
    """
    Queries OpenAI or Ollama, passing details of the triggered alert and host.
    Falls back to offline generator if query fails or no keys exist.
    """
    details = alert.trigger_details or {}
    proc_info = details.get("process", {})
    cmdline = proc_info.get("command_line", "N/A")
    user = proc_info.get("username", device.logged_in_user)

    user_content = f"""
    --- ALERT DETAILS ---
    Title: {alert.title}
    Severity: {alert.severity}
    MITRE Tactic: {alert.mitre_tactic}
    MITRE Technique: {alert.mitre_technique}
    Confidence Score: {alert.confidence_score}%
    Trigger Process PID: {alert.trigger_process_pid}
    Process Command Line: {cmdline}
    Process Owner: {user}

    --- DEVICE METADATA ---
    Device ID: {device.device_id}
    Hostname: {device.hostname}
    OS: {device.os_name} {device.os_version}
    Risk Score: {device.risk_score}/100
    """

    # 1. Try OpenAI if key is configured
    if settings.OPENAI_API_KEY:
        try:
            logger.info("Initiating OpenAI Copilot Investigation...")
            from openai import OpenAI
            client = OpenAI(api_key=settings.OPENAI_API_KEY)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content}
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                timeout=15
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            logger.error(f"OpenAI investigation failed: {e}. Falling back to Ollama / Offline.")

    # 2. Try Ollama (Local Server)
    if settings.OLLAMA_HOST:
        try:
            logger.info("Initiating Ollama Copilot Investigation...")
            # We will use the chat or generate endpoint
            # We assume a default lightweight model is pulled, e.g. llama3, llama3.1, or mistral.
            # In a container, host.docker.internal resolves to the host's localhost.
            url = f"{settings.OLLAMA_HOST}/api/chat"
            payload = {
                "model": "llama3",  # default fallback model name
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content}
                ],
                "stream": False,
                "format": "json"
            }
            with httpx.Client() as client:
                response = client.post(url, json=payload, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    content = data.get("message", {}).get("content", "")
                    return json.loads(content)
        except Exception as e:
            logger.error(f"Ollama investigation failed: {e}. Falling back to Offline.")

    # 3. Fallback: Offline High-Fidelity Detections Explanation
    logger.info("Using offline heuristic compiler for copilot investigation.")
    return generate_offline_analysis(alert, device)
