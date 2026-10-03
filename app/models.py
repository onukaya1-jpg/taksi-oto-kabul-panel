"""
Database Models — SQLAlchemy Async
====================================
License, Device, and Token tracking tables.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index, func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class License(Base):
    """License key records."""
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    license_key = Column(String(32), unique=True, nullable=False, index=True)
    plan = Column(String(32), nullable=False, default="monthly")  # hourly | minute | daily | weekly | monthly | custom | lifetime | admin
    product = Column(String(32), nullable=False, default="gamestore", server_default="gamestore")  # gamestore | taksi
    hwid = Column(String(64), nullable=True)  # bound device HWID (null = unbound)
    is_active = Column(Boolean, default=True, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    activated_at = Column(DateTime(timezone=True), nullable=True)  # first use timestamp
    expires_at = Column(DateTime(timezone=True), nullable=True)
    duration_days = Column(Integer, nullable=True)  # expiry starts on first use, not creation
    duration_minutes = Column(Integer, nullable=True)  # sub-day durations (hourly/minute plans)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_ip = Column(String(45), nullable=True)
    max_devices = Column(Integer, default=1)
    notes = Column(Text, nullable=True)

    devices = relationship("Device", back_populates="license", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<License key={self.license_key[:8]}... plan={self.plan} active={self.is_active}>"


class Device(Base):
    """Registered device records (HWID binding)."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    license_id = Column(Integer, ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False)
    device_hwid = Column(String(64), nullable=False)
    device_fingerprint = Column(Text, nullable=True)  # extended fingerprint data
    registered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_ip = Column(String(45), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    user_agent = Column(String(128), nullable=True)

    license = relationship("License", back_populates="devices")

    __table_args__ = (
        UniqueConstraint("license_id", "device_hwid", name="uq_license_device"),
        Index("ix_devices_hwid", "device_hwid"),
    )

    def __repr__(self) -> str:
        return f"<Device hwid={self.device_hwid[:8]}... license_id={self.license_id}>"


class TokenLog(Base):
    """Token issuance and verification log."""
    __tablename__ = "token_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    license_id = Column(Integer, ForeignKey("licenses.id", ondelete="SET NULL"), nullable=True)
    device_hwid = Column(String(64), nullable=False)
    token_nonce = Column(String(64), nullable=False, index=True)
    action = Column(String(32), nullable=False)  # issue | verify | refresh | revoke
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_valid = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_token_logs_created", "created_at"),
    )


class SecurityEvent(Base):
    """Security event records (threats, anomalies)."""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(64), nullable=False, index=True)
    device_hwid = Column(String(64), nullable=True)
    ip_address = Column(String(45), nullable=True)
    detail = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False, default="warning")  # info | warning | critical
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_security_events_created", "created_at"),
    )


# ============================================================
# Admin Panel — Online Tracking & Remote Control Models
# ============================================================

class OnlineSession(Base):
    """Tracks user online/offline sessions with duration."""
    __tablename__ = "online_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    license_id = Column(Integer, ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False)
    device_hwid = Column(String(64), nullable=False)
    character_name = Column(String(64), nullable=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ended_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    ip_address = Column(String(45), nullable=True)

    __table_args__ = (
        Index("ix_online_sessions_license", "license_id"),
        Index("ix_online_sessions_hwid", "device_hwid"),
        Index("ix_online_sessions_started", "started_at"),
    )


class BotStatus(Base):
    """Real-time bot status reported via heartbeat (one row per device)."""
    __tablename__ = "bot_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    license_id = Column(Integer, ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False)
    device_hwid = Column(String(64), nullable=False, unique=True, index=True)
    bot_running = Column(Boolean, default=False)
    game_connected = Column(Boolean, default=False)
    character_name = Column(String(64), nullable=True)
    bot_state = Column(String(32), nullable=True)  # idle, searching, attacking, looting, etc.
    mobs_killed = Column(Integer, default=0)
    items_collected = Column(Integer, default=0)
    death_count = Column(Integer, default=0)
    potions_used = Column(Integer, default=0)
    uptime_seconds = Column(Integer, default=0)
    hp = Column(Integer, default=0)
    max_hp = Column(Integer, default=0)
    mp = Column(Integer, default=0)
    max_mp = Column(Integer, default=0)
    pos_x = Column(Integer, default=0)
    pos_y = Column(Integer, default=0)
    last_updated = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_bot_status_license", "license_id"),
    )


class AdminCommandQueue(Base):
    """Commands queued by admin to be delivered to clients via heartbeat."""
    __tablename__ = "admin_commands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_hwid = Column(String(64), nullable=False, index=True)
    action = Column(String(32), nullable=False)  # stop_bot, start_bot, restart_bot, disconnect, show_message, kill_session
    param = Column(Text, nullable=True)  # e.g. message text for show_message
    signature = Column(String(64), nullable=True)  # HMAC-SHA256 signature for command integrity
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    delivered = Column(Boolean, default=False)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
