from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..database import get_db
from ..models import Device, Alert, Process, NetworkConnection, FileEvent, Investigation
from ..schemas import AlertResponse, AlertUpdate, ProcessResponse, NetworkConnectionResponse, FileEventResponse, InvestigationResponse
from ..ai_copilot import analyze_incident_with_ai
from ..rules import recalculate_device_risk

router = APIRouter(prefix="/api")

@router.get("/device/{device_id}/alerts", response_model=List[AlertResponse])
def get_device_alerts(device_id: str, db: Session = Depends(get_db)):
    # Verify device exists
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return db.query(Alert).filter(Alert.device_id == device_id).order_by(Alert.created_at.desc()).all()

@router.get("/device/{device_id}/processes", response_model=List[ProcessResponse])
def get_device_processes(device_id: str, db: Session = Depends(get_db)):
    return db.query(Process).filter(Process.device_id == device_id).all()

@router.get("/device/{device_id}/connections", response_model=List[NetworkConnectionResponse])
def get_device_connections(device_id: str, db: Session = Depends(get_db)):
    return db.query(NetworkConnection).filter(NetworkConnection.device_id == device_id).all()

@router.get("/device/{device_id}/file-events", response_model=List[FileEventResponse])
def get_device_file_events(device_id: str, db: Session = Depends(get_db)):
    return db.query(FileEvent).filter(FileEvent.device_id == device_id).order_by(FileEvent.timestamp.desc()).limit(100).all()

@router.put("/alert/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    
    # Update host risk based on resolution
    recalculate_device_risk(db, alert.device_id)
    return alert

@router.post("/device/{device_id}/ai-investigate", response_model=InvestigationResponse)
def request_ai_investigate(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device_info = {
        "hostname": device.hostname,
        "os_name": device.os_name,
        "os_version": device.os_version,
        "ip_address": device.ip_address,
        "logged_in_user": device.logged_in_user,
        "risk_score": device.risk_score
    }

    # Gather active alerts (unresolved)
    unresolved_alerts = db.query(Alert).filter(Alert.device_id == device_id, Alert.status == "UNRESOLVED").all()

    # Query Copilot service (OpenAI or Local Template)
    ai_result = analyze_incident_with_ai(device_info, unresolved_alerts)

    # Save to investigation history
    investigation = Investigation(
        device_id=device_id,
        summary=ai_result.get("summary", ""),
        analysis=ai_result.get("analysis", ""),
        remediation=ai_result.get("remediation", "")
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)

    return investigation

@router.get("/device/{device_id}/investigations", response_model=List[InvestigationResponse])
def get_investigations(device_id: str, db: Session = Depends(get_db)):
    return db.query(Investigation).filter(Investigation.device_id == device_id).order_by(Investigation.created_at.desc()).all()
