from pydantic import BaseModel, Field
from typing import List, Optional, Any
from datetime import datetime

# --- Process Schemas ---
class ProcessBase(BaseModel):
    pid: int
    ppid: Optional[int] = None
    name: str
    exe_path: Optional[str] = None
    command_line: Optional[str] = None
    username: Optional[str] = None
    sha256_hash: Optional[str] = None
    cpu_percent: Optional[float] = 0.0
    memory_percent: Optional[float] = 0.0

class ProcessCreate(ProcessBase):
    pass

class ProcessOut(ProcessBase):
    id: int
    device_id: str
    timestamp: datetime

    class Config:
        from_attributes = True


# --- Network Connection Schemas ---
class NetworkConnectionBase(BaseModel):
    pid: Optional[int] = None
    protocol: Optional[str] = None
    local_address: Optional[str] = None
    local_port: Optional[int] = None
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    state: Optional[str] = None
    reputation_status: Optional[str] = "unverified"

class NetworkConnectionCreate(NetworkConnectionBase):
    pass

class NetworkConnectionOut(NetworkConnectionBase):
    id: int
    device_id: str
    timestamp: datetime

    class Config:
        from_attributes = True


# --- Telemetry Ingestion Schemas ---
class TelemetrySubmit(BaseModel):
    device_id: str
    hostname: str
    os_name: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    cpu_usage: Optional[float] = 0.0
    ram_usage: Optional[float] = 0.0
    logged_in_user: Optional[str] = None
    processes: List[ProcessCreate] = []
    network_connections: List[NetworkConnectionCreate] = []


# --- Device Schemas ---
class DeviceBase(BaseModel):
    device_id: str
    hostname: str
    os_name: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    cpu_usage: Optional[float] = 0.0
    ram_usage: Optional[float] = 0.0
    logged_in_user: Optional[str] = None
    risk_score: Optional[int] = 0
    status: Optional[str] = "offline"

class DeviceOut(DeviceBase):
    last_seen: datetime
    dashboard_token: str
    created_at: datetime

    class Config:
        from_attributes = True


# --- Registration & Auth Schemas ---
class DeviceRegister(BaseModel):
    hostname: str
    os_name: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    logged_in_user: Optional[str] = None
    registration_key: Optional[str] = None

class DeviceRegisterOut(BaseModel):
    device_id: str
    device_token: str
    dashboard_token: str
    dashboard_url: str

class AdminLogin(BaseModel):
    password: str

class AdminToken(BaseModel):
    access_token: str
    token_type: str



# --- Alert Schemas ---
class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence_score: Optional[int] = 50
    trigger_process_pid: Optional[int] = None
    trigger_details: Optional[Any] = None
    resolved: Optional[bool] = False

class AlertCreate(AlertBase):
    device_id: str

class AlertOut(AlertBase):
    id: int
    device_id: str
    timestamp: datetime

    class Config:
        from_attributes = True


# --- Timeline Event Schema ---
class TimelineEvent(BaseModel):
    id: str  # unique synthetic id
    event_type: str  # 'process_started', 'network_connection', 'alert'
    title: str
    description: str
    timestamp: datetime
    severity: Optional[str] = "info"  # low, medium, high, critical, info
    details: Optional[dict] = None


# --- AI Investigation Schemas ---
class InvestigationRequest(BaseModel):
    incident_id: Optional[int] = None  # If investigating a specific alert
    custom_query: Optional[str] = None # Or general question

class InvestigationResponse(BaseModel):
    summary: str
    mitre_explanation: str
    timeline_explanation: str
    remediation_steps: str
    risk_score_explanation: str


# --- Report Schemas ---
class InvestigationReportOut(BaseModel):
    id: int
    device_id: str
    summary: str
    timeline_explanation: str
    remediation_steps: str
    risk_breakdown: str
    created_at: datetime

    class Config:
        from_attributes = True
