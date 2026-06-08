from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Device, Process, NetworkConnection, FileEvent
from ..schemas import TelemetryIngest
from ..rules import run_rules_engine
import datetime

router = APIRouter(prefix="/api")

@router.post("/telemetry")
def ingest_telemetry(payload: TelemetryIngest, db: Session = Depends(get_db)):
    """
    Receives system data from the endpoint agent. 
    Inserts / updates the device, lists processes, records sockets, logs file edits,
    and runs threat rules.
    """
    # 1. Update or Create Device
    device = db.query(Device).filter(Device.id == payload.device_id).first()
    if not device:
        device = Device(
            id=payload.device_id,
            hostname=payload.hostname,
            os_name=payload.os_name,
            os_version=payload.os_version,
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            logged_in_user=payload.logged_in_user
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    else:
        # Update device dynamic status
        device.hostname = payload.hostname
        device.os_name = payload.os_name
        device.os_version = payload.os_version
        device.ip_address = payload.ip_address
        device.logged_in_user = payload.logged_in_user
        device.cpu_usage = payload.cpu_usage
        device.memory_usage = payload.memory_usage
        device.last_seen = datetime.datetime.utcnow()

    # 2. Sync Live Process Tree (Clear old list and write new list)
    db.query(Process).filter(Process.device_id == payload.device_id).delete()
    for proc in payload.processes:
        db_proc = Process(
            device_id=payload.device_id,
            pid=proc.pid,
            ppid=proc.ppid,
            name=proc.name,
            exe=proc.exe,
            cmdline=proc.cmdline,
            username=proc.username,
            sha256=proc.sha256
        )
        db.add(db_proc)

    # 3. Sync Active Network Connections (Sockets)
    db.query(NetworkConnection).filter(NetworkConnection.device_id == payload.device_id).delete()
    for conn in payload.connections:
        db_conn = NetworkConnection(
            device_id=payload.device_id,
            pid=conn.pid,
            process_name=conn.process_name,
            family=conn.family,
            type=conn.type,
            laddr=conn.laddr,
            raddr=conn.raddr,
            status=conn.status
        )
        db.add(db_conn)

    # 4. Append File Events (historical log, don't clear)
    for fe in payload.file_events:
        db_fe = FileEvent(
            device_id=payload.device_id,
            action=fe.action,
            filepath=fe.filepath
        )
        db.add(db_fe)

    db.commit()

    # 5. Run Detection Heuristics & Update Device Risk
    run_rules_engine(db, payload.device_id, payload)

    return {"status": "success", "message": "Telemetry processed successfully"}
