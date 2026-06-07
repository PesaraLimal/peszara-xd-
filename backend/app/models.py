from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base

class Device(Base):
    __tablename__ = "devices"

    device_id = Column(String(255), primary_key=True, index=True)
    hostname = Column(String(255), nullable=False)
    os_name = Column(String(255), nullable=False)
    os_version = Column(String(255))
    ip_address = Column(String(45))
    mac_address = Column(String(17))
    cpu_usage = Column(Float, default=0.0)
    ram_usage = Column(Float, default=0.0)
    logged_in_user = Column(String(255))
    risk_score = Column(Integer, default=0)
    status = Column(String(50), default="offline")
    last_seen = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    device_token = Column(String(255), nullable=False, unique=True)
    dashboard_token = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=func.now())

    processes = relationship("Process", back_populates="device", cascade="all, delete-orphan")
    network_connections = relationship("NetworkConnection", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    reports = relationship("InvestigationReport", back_populates="device", cascade="all, delete-orphan")


class Process(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(255), ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
    pid = Column(Integer, nullable=False)
    ppid = Column(Integer)
    name = Column(String(255), nullable=False)
    exe_path = Column(Text)
    command_line = Column(Text)
    username = Column(String(255))
    sha256_hash = Column(String(64))
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    timestamp = Column(DateTime(timezone=True), default=func.now())

    device = relationship("Device", back_populates="processes")


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(255), ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
    pid = Column(Integer)
    protocol = Column(String(10))
    local_address = Column(String(45))
    local_port = Column(Integer)
    remote_address = Column(String(45))
    remote_port = Column(Integer)
    state = Column(String(50))
    reputation_status = Column(String(100), default="unverified")
    timestamp = Column(DateTime(timezone=True), default=func.now())

    device = relationship("Device", back_populates="network_connections")


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    indicator = Column(String(255), primary_key=True, index=True)
    indicator_type = Column(String(50), nullable=False)  # 'file_hash', 'ip_address'
    reputation = Column(String(50), nullable=False)      # 'clean', 'suspicious', 'malicious'
    raw_response = Column(JSON)
    cached_at = Column(DateTime(timezone=True), default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(255), ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(50), nullable=False)        # 'low', 'medium', 'high', 'critical'
    mitre_tactic = Column(String(100))                   # 'Execution', 'Persistence', etc.
    mitre_technique = Column(String(100))                # e.g., 'T1059.001'
    confidence_score = Column(Integer, default=50)
    trigger_process_pid = Column(Integer)
    trigger_details = Column(JSON)
    resolved = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=func.now())

    device = relationship("Device", back_populates="alerts")


class InvestigationReport(Base):
    __tablename__ = "investigation_reports"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(255), ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
    summary = Column(Text, nullable=False)
    timeline_explanation = Column(Text, nullable=False)
    remediation_steps = Column(Text, nullable=False)
    risk_breakdown = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())

    device = relationship("Device", back_populates="reports")
