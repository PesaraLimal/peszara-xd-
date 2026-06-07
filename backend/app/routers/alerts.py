from fastapi import APIRouter, Depends, HTTPException
from app.auth import check_device_access
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.database import get_db
from app.models import Device, Alert, Process, NetworkConnection
from app.schemas import AlertOut, TimelineEvent
from app.detection.engine import calculate_risk_score

router = APIRouter(prefix="/api/v1/devices", tags=["Alerts & Timeline"])

@router.get("/{device_id}/alerts", response_model=List[AlertOut], dependencies=[Depends(check_device_access)])
def get_device_alerts(device_id: str, resolved: Optional[bool] = None, db: Session = Depends(get_db)):
    """
    Returns alerts list for a specific device. Filters by resolved status if specified.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
        
    query = db.query(Alert).filter(Alert.device_id == device_id)
    if resolved is not None:
        query = query.filter(Alert.resolved == resolved)
        
    return query.order_by(Alert.timestamp.desc()).all()


@router.post("/{device_id}/alerts/{alert_id}/resolve", dependencies=[Depends(check_device_access)])
def resolve_alert(device_id: str, alert_id: int, db: Session = Depends(get_db)):
    """
    Marks a specific alert as resolved and re-evaluates the device risk score.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
        
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.device_id == device_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found for device '{device_id}'.")
        
    alert.resolved = True
    db.flush()
    
    # Recalculate Risk Score
    active_alerts = db.query(Alert).filter(Alert.device_id == device_id, Alert.resolved == False).all()
    device.risk_score = calculate_risk_score(active_alerts)
    if device.risk_score >= 70:
        device.status = "critical"
    elif device.risk_score >= 30:
        device.status = "suspicious"
    else:
        device.status = "online"
        
    db.commit()
    return {"status": "success", "risk_score": device.risk_score}


@router.post("/{device_id}/alerts/resolve-all", dependencies=[Depends(check_device_access)])
def resolve_all_alerts(device_id: str, db: Session = Depends(get_db)):
    """
    Marks all unresolved alerts for a specific device as resolved and resets the device risk score.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
        
    db.query(Alert).filter(Alert.device_id == device_id, Alert.resolved == False).update({Alert.resolved: True})
    device.risk_score = 0
    device.status = "online"
    db.commit()
    return {"status": "success", "risk_score": 0}



@router.get("/{device_id}/timeline", response_model=List[TimelineEvent], dependencies=[Depends(check_device_access)])
def get_device_timeline(device_id: str, limit: int = 100, db: Session = Depends(get_db)):
    """
    Combines alerts, process starts, and network connections into a chronological stream.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    events = []

    # 1. Fetch Alerts
    alerts = db.query(Alert).filter(Alert.device_id == device_id).order_by(Alert.timestamp.desc()).limit(limit).all()
    for alert in alerts:
        events.append(TimelineEvent(
            id=f"alert-{alert.id}",
            event_type="alert",
            title=alert.title,
            description=f"[{alert.mitre_tactic or 'Threat'}] {alert.description}",
            timestamp=alert.timestamp,
            severity=alert.severity,
            details={"tactic": alert.mitre_tactic, "technique": alert.mitre_technique, "pid": alert.trigger_process_pid}
        ))

    # 2. Fetch Processes
    processes = db.query(Process).filter(Process.device_id == device_id).order_by(Process.timestamp.desc()).limit(limit).all()
    for proc in processes:
        events.append(TimelineEvent(
            id=f"process-{proc.id}",
            event_type="process_started",
            title=f"Process Spawned: {proc.name}",
            description=f"PID {proc.pid} executed by {proc.username or 'SYSTEM'}. Command: {proc.command_line or 'N/A'}",
            timestamp=proc.timestamp,
            severity="info",
            details={"pid": proc.pid, "ppid": proc.ppid, "exe_path": proc.exe_path, "sha256": proc.sha256_hash}
        ))

    # 3. Fetch Network Connections
    connections = db.query(NetworkConnection).filter(NetworkConnection.device_id == device_id).order_by(NetworkConnection.timestamp.desc()).limit(limit).all()
    for conn in connections:
        events.append(TimelineEvent(
            id=f"net-{conn.id}",
            event_type="network_connection",
            title=f"Socket Established: {conn.remote_address}:{conn.remote_port}",
            description=f"Process PID {conn.pid} opened {conn.protocol} connection to {conn.remote_address}:{conn.remote_port} ({conn.state})",
            timestamp=conn.timestamp,
            severity="info",
            details={"pid": conn.pid, "protocol": conn.protocol, "remote_ip": conn.remote_address, "remote_port": conn.remote_port}
        ))

    # Sort all events chronologically descending (newest first)
    events.sort(key=lambda x: x.timestamp, reverse=True)
    return events[:limit]
