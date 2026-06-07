import logging
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from datetime import datetime
from app.database import get_db
from app.schemas import TelemetrySubmit
from app.models import Device, Process, NetworkConnection, Alert
from app.detection.engine import analyze_device_telemetry, calculate_risk_score

logger = logging.getLogger("PeszaraTelemetryRouter")
router = APIRouter(prefix="/api/v1/telemetry", tags=["Telemetry"])

@router.post("/submit")
def submit_telemetry(
    payload: TelemetrySubmit,
    x_device_id: str = Header(None),
    x_device_token: str = Header(None),
    x_dashboard_token: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Ingests live telemetry packets from agents. Refreshes processes/connections lists,
    runs threat rules, stores alerts, and recalculates the host risk score.
    """
    device_id = x_device_id or payload.device_id
    
    try:
        # 1. Fetch Device record
        device = db.query(Device).filter(Device.device_id == device_id).first()
        
        if not device:
            # Auto-enroll device if not already registered
            import secrets
            device_token = f"token_{secrets.token_hex(16)}"
            dashboard_token = f"dash_{secrets.token_hex(16)}"
            device = Device(
                device_id=device_id or f"device_{secrets.token_hex(4)}",
                hostname=payload.hostname,
                os_name=payload.os_name,
                os_version=payload.os_version,
                ip_address=payload.ip_address,
                mac_address=payload.mac_address,
                logged_in_user=payload.logged_in_user,
                device_token=device_token,
                dashboard_token=dashboard_token,
                status="online"
            )
            db.add(device)
            db.flush()
            device_id = device.device_id
            
        if True:
            # Update dynamic hardware stats & metadata
            device.hostname = payload.hostname
            device.os_name = payload.os_name
            device.os_version = payload.os_version
            device.ip_address = payload.ip_address
            device.mac_address = payload.mac_address
            device.cpu_usage = payload.cpu_usage
            device.ram_usage = payload.ram_usage
            device.logged_in_user = payload.logged_in_user
            device.status = "online"
            device.last_seen = datetime.utcnow()

        # 2. Clear old state data (processes & sockets)
        db.query(Process).filter(Process.device_id == device_id).delete()
        db.query(NetworkConnection).filter(NetworkConnection.device_id == device_id).delete()
        db.flush()

        # 3. Add fresh process metrics
        for p in payload.processes:
            proc_record = Process(
                device_id=device_id,
                pid=p.pid,
                ppid=p.ppid,
                name=p.name,
                exe_path=p.exe_path,
                command_line=p.command_line,
                username=p.username,
                sha256_hash=p.sha256_hash,
                cpu_percent=p.cpu_percent,
                memory_percent=p.memory_percent
            )
            db.add(proc_record)

        # 4. Add fresh network connection details
        for c in payload.network_connections:
            conn_record = NetworkConnection(
                device_id=device_id,
                pid=c.pid,
                protocol=c.protocol,
                local_address=c.local_address,
                local_port=c.local_port,
                remote_address=c.remote_address,
                remote_port=c.remote_port,
                state=c.state
            )
            db.add(conn_record)
        
        db.flush()

        # 5. Run Threat Detection rules
        # Convert Pydantic schemas to dictionaries for the engine to inspect
        proc_dicts = [p.model_dump() for p in payload.processes]
        conn_dicts = [c.model_dump() for c in payload.network_connections]

        new_alerts = analyze_device_telemetry(db, device_id, proc_dicts, conn_dicts)

        for alert in new_alerts:
            # Check for active alert duplicates to avoid noise (match by title, pid, and status resolved=False)
            exists = db.query(Alert).filter(
                Alert.device_id == device_id,
                Alert.title == alert.title,
                Alert.trigger_process_pid == alert.trigger_process_pid,
                Alert.resolved == False
            ).first()

            if not exists:
                db.add(alert)
                logger.info(f"ALERT TRIGGERED on {device_id}: {alert.title} (Severity: {alert.severity})")

        db.flush()

        # 6. Recalculate Risk Score
        active_alerts = db.query(Alert).filter(Alert.device_id == device_id, Alert.resolved == False).all()
        risk_score = calculate_risk_score(active_alerts)
        device.risk_score = risk_score
        
        # Adjust status labels dynamically based on severity risks
        if risk_score >= 70:
            device.status = "critical"
        elif risk_score >= 30:
            device.status = "suspicious"
        else:
            device.status = "online"

        db.commit()
        return {"status": "success", "device_id": device_id, "risk_score": risk_score}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error submitting telemetry data: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database submission failed: {str(e)}")
