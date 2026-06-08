from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime

# Base Schemas
class ProcessBase(BaseModel):
    pid: int
    ppid: Optional[int] = None
    name: str
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None
    sha256: Optional[str] = None

class ProcessCreate(ProcessBase):
    pass

class ProcessResponse(ProcessBase):
    id: int
    device_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# Sockets / Connections
class NetworkConnectionBase(BaseModel):
    pid: Optional[int] = None
    process_name: Optional[str] = None
    family: Optional[str] = None
    type: Optional[str] = None
    laddr: Optional[str] = None
    raddr: Optional[str] = None
    status: Optional[str] = None

class NetworkConnectionCreate(NetworkConnectionBase):
    pass

class NetworkConnectionResponse(NetworkConnectionBase):
    id: int
    device_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# File Activity
class FileEventBase(BaseModel):
    action: str
    filepath: str

class FileEventCreate(FileEventBase):
    pass

class FileEventResponse(FileEventBase):
    id: int
    device_id: str
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)

# Device Schemas
class DeviceBase(BaseModel):
    id: str
    hostname: str
    os_name: str
    os_version: str
    ip_address: str
    mac_address: Optional[str] = None
    logged_in_user: Optional[str] = None
    cpu_usage: Optional[float] = 0.0
    memory_usage: Optional[float] = 0.0

class DeviceCreate(DeviceBase):
    pass

class DeviceResponse(DeviceBase):
    risk_score: float
    last_seen: datetime
    model_config = ConfigDict(from_attributes=True)

# Alerts
class AlertBase(BaseModel):
    title: str
    description: str
    severity: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: Optional[str] = "UNRESOLVED"

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    status: str

class AlertResponse(AlertBase):
    id: int
    device_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# Investigations
class InvestigationBase(BaseModel):
    summary: Optional[str] = None
    analysis: Optional[str] = None
    remediation: Optional[str] = None

class InvestigationResponse(InvestigationBase):
    id: int
    device_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# Comprehensive Telemetry Payload
class TelemetryIngest(BaseModel):
    device_id: str
    hostname: str
    os_name: str
    os_version: str
    ip_address: str
    mac_address: Optional[str] = None
    logged_in_user: Optional[str] = None
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    processes: List[ProcessCreate] = []
    connections: List[NetworkConnectionCreate] = []
    file_events: List[FileEventCreate] = []
