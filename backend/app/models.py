from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
import datetime
from .database import Base

class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, index=True) # Unique device ID (e.g. system UUID/MAC)
    hostname = Column(String, nullable=False)
    os_name = Column(String, nullable=False)
    os_version = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    mac_address = Column(String)
    logged_in_user = Column(String)
    cpu_usage = Column(Float, default=0.0)
    memory_usage = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    processes = relationship("Process", back_populates="device", cascade="all, delete-orphan")
    connections = relationship("NetworkConnection", back_populates="device", cascade="all, delete-orphan")
    file_events = relationship("FileEvent", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    investigations = relationship("Investigation", back_populates="device", cascade="all, delete-orphan")

class Process(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    pid = Column(Integer, nullable=False)
    ppid = Column(Integer)
    name = Column(String, nullable=False)
    exe = Column(String)
    cmdline = Column(String)
    username = Column(String)
    sha256 = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="processes")

class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    pid = Column(Integer)
    process_name = Column(String)
    family = Column(String)
    type = Column(String)
    laddr = Column(String)
    raddr = Column(String)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="connections")

class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    action = Column(String, nullable=False) # CREATED, MODIFIED, DELETED
    filepath = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="file_events")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    mitre_tactic = Column(String)             # Execution, Persistence, etc.
    mitre_technique = Column(String)          # e.g., T1059
    status = Column(String, default="UNRESOLVED") # UNRESOLVED, INVESTIGATING, RESOLVED
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="alerts")

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    summary = Column(Text)
    analysis = Column(Text)
    remediation = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="investigations")
