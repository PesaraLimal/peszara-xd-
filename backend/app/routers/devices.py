import secrets
from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import Device, Process, NetworkConnection
from app.schemas import (
    DeviceOut, ProcessOut, NetworkConnectionOut,
    DeviceRegister, DeviceRegisterOut, AdminLogin, AdminToken
)
from app.auth import verify_admin_token, check_device_access, create_admin_token, auth_header_sec
from app.config import settings

router = APIRouter(prefix="/api/v1/devices", tags=["Devices"])

@router.post("/register", response_model=DeviceRegisterOut)
def register_device(payload: DeviceRegister, db: Session = Depends(get_db)):
    """
    Registers a new device endpoint.
    """
        
    # Generate unique device_id
    device_id = f"device_{secrets.token_hex(4)}"
    while db.query(Device).filter(Device.device_id == device_id).first():
        device_id = f"device_{secrets.token_hex(4)}"
        
    device_token = f"token_{secrets.token_hex(16)}"
    dashboard_token = f"dash_{secrets.token_hex(16)}"
    
    device = Device(
        device_id=device_id,
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
    
    try:
        db.add(device)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database enrollment failed: {str(e)}")
        
    return DeviceRegisterOut(
        device_id=device_id,
        device_token=device_token,
        dashboard_token=dashboard_token,
        dashboard_url=f"/device/{device_id}?token={dashboard_token}"
    )


@router.post("/auth/login", response_model=AdminToken)
def login_admin(payload: AdminLogin):
    """
    Validates the admin password and issues a stateless session token.
    """
    if payload.password != settings.ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid administrator password.")
    
    token = create_admin_token()
    return AdminToken(access_token=token, token_type="bearer")


@router.get("", response_model=List[DeviceOut])
def get_all_devices(db: Session = Depends(get_db)):
    """
    Returns list of all registered devices.
    """
    return db.query(Device).all()


@router.get("/{device_id}", response_model=DeviceOut, dependencies=[Depends(check_device_access)])
def get_device_by_id(device_id: str, db: Session = Depends(get_db)):
    """
    Returns metadata for a specific device. Enforces device scope.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")
    return device


@router.get("/{device_id}/processes", response_model=List[ProcessOut], dependencies=[Depends(check_device_access)])
def get_device_processes(device_id: str, db: Session = Depends(get_db)):
    """
    Returns list of active processes for a specific device.
    """
    return db.query(Process).filter(Process.device_id == device_id).order_by(Process.pid.asc()).all()


@router.get("/{device_id}/network", response_model=List[NetworkConnectionOut], dependencies=[Depends(check_device_access)])
def get_device_network_connections(device_id: str, db: Session = Depends(get_db)):
    """
    Returns active network connections for a specific device.
    """
    return db.query(NetworkConnection).filter(NetworkConnection.device_id == device_id).order_by(NetworkConnection.timestamp.desc()).all()
