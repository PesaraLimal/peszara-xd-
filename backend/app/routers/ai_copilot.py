from fastapi import APIRouter, Depends, HTTPException
from app.auth import check_device_access
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Device, Alert, InvestigationReport
from app.schemas import InvestigationRequest, InvestigationResponse, InvestigationReportOut
from app.ai.copilot import investigate_incident

router = APIRouter(prefix="/api/v1/devices", tags=["AI Copilot & Reports"])

@router.post("/{device_id}/copilot/investigate", response_model=InvestigationResponse, dependencies=[Depends(check_device_access)])
def run_copilot_investigation(device_id: str, payload: InvestigationRequest, db: Session = Depends(get_db)):
    """
    Executes an AI-driven security analysis of an alert using either local Ollama or OpenAI.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    if not payload.incident_id:
        # If no specific alert, look for the most severe unresolved alert
        alert = db.query(Alert).filter(
            Alert.device_id == device_id,
            Alert.resolved == False
        ).order_by(Alert.severity.desc(), Alert.timestamp.desc()).first()
        
        # If still no alert, look for resolved ones
        if not alert:
            alert = db.query(Alert).filter(Alert.device_id == device_id).order_by(Alert.timestamp.desc()).first()
    else:
        alert = db.query(Alert).filter(Alert.id == payload.incident_id, Alert.device_id == device_id).first()

    if not alert:
        # Return generic clean investigation if no threats exist
        return InvestigationResponse(
            summary=f"No security alerts have been triggered on device '{device.hostname}'.",
            mitre_explanation="The system behavior aligns with standard host operations; no malicious MITRE techniques detected.",
            timeline_explanation="Timeline indicates normal operational cycles with no threat flags.",
            remediation_steps="Maintain active monitoring and ensure the agent stays online.",
            risk_score_explanation=f"Device risk score is currently {device.risk_score}/100, which is considered low risk."
        )

    try:
        analysis = investigate_incident(alert, device)
        return InvestigationResponse(
            summary=analysis.get("summary", "Analysis unavailable."),
            mitre_explanation=analysis.get("mitre_explanation", "MITRE lookup failed."),
            timeline_explanation=analysis.get("timeline_explanation", "Timeline compilation failed."),
            remediation_steps=analysis.get("remediation_steps", "Remediation recommendations unavailable."),
            risk_score_explanation=analysis.get("risk_score_explanation", "Risk analysis failed.")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Investigation failed: {str(e)}")


@router.post("/{device_id}/reports/generate", response_model=InvestigationReportOut, dependencies=[Depends(check_device_access)])
def generate_incident_report(device_id: str, db: Session = Depends(get_db)):
    """
    Synthesizes and exports a full threat assessment report for the device.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    # Get unresolved alerts
    alerts = db.query(Alert).filter(Alert.device_id == device_id, Alert.resolved == False).all()
    if not alerts:
        # Look for recently resolved alerts
        alerts = db.query(Alert).filter(Alert.device_id == device_id).order_by(Alert.timestamp.desc()).limit(5).all()

    # Create detailed parts of report
    summary = f"Security status report for hostname: {device.hostname} ({device.os_name}). "
    if not alerts:
        summary += "No active indicators of compromise (IoCs) were identified. Host is clean."
        timeline_explanation = "The device telemetry matches stable operational baseline conditions."
        remediation_steps = "No corrective action is required at this time."
        risk_breakdown = f"Risk score is {device.risk_score}/100. There are no active threats impacting the score."
    else:
        summary += f"The host has {len(alerts)} active unresolved security alerts. Immediate containment is advised."
        
        # Compile MITRE details
        tactic_counts = {}
        for alert in alerts:
            t = alert.mitre_tactic or "Execution"
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
        
        risk_breakdown = f"Current Device Risk Score: {device.risk_score}/100.\n"
        for t, count in tactic_counts.items():
            risk_breakdown += f"- {count} alert(s) mapped to MITRE Tactic: {t}\n"

        timeline_explanation = "Timeline Incident Flow Analysis:\n"
        for idx, alert in enumerate(alerts, 1):
            timeline_explanation += f"{idx}. Alert: {alert.title} (Severity: {alert.severity.upper()}) triggered at {alert.timestamp.strftime('%H:%M:%S')} - Details: {alert.description}\n"

        remediation_steps = "Incident Containment Actions Required:\n"
        remediation_steps += "1. Enforce network isolation on the device immediately.\n"
        remediation_steps += "2. Terminate the process IDs associated with the triggered alerts:\n"
        for alert in alerts:
            if alert.trigger_process_pid:
                remediation_steps += f"   - PID {alert.trigger_process_pid} (associated with alert: '{alert.title}')\n"
        remediation_steps += "3. Search for secondary payloads and trace connection endpoints in network logs.\n"
        remediation_steps += "4. Conduct full host credentials rotation."

    report = InvestigationReport(
        device_id=device_id,
        summary=summary,
        timeline_explanation=timeline_explanation,
        remediation_steps=remediation_steps,
        risk_breakdown=risk_breakdown
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return report
