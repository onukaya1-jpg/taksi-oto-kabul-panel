"""
Audit Logger — Structured Security Event Logging
==================================================
JSON-lines audit log with:
  - All auth events (success/failure)
  - Token issuance, verification, refresh
  - Device registration
  - Security alerts
  - Rate limit violations

Outputs to:
  - Local JSONL file (always)
  - Stdout structured log (always)
  - Loki / Elasticsearch (if configured)
"""

import json
import os
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class AuditEventType(str, Enum):
    """Audit event categories."""
    DEVICE_REGISTER = "device.register"
    DEVICE_REGISTER_FAIL = "device.register.fail"
    TOKEN_ISSUE = "token.issue"
    TOKEN_ISSUE_FAIL = "token.issue.fail"
    TOKEN_VERIFY = "token.verify"
    TOKEN_VERIFY_FAIL = "token.verify.fail"
    TOKEN_REFRESH = "token.refresh"
    TOKEN_REFRESH_FAIL = "token.refresh.fail"
    FEATURE_USE = "feature.use"
    FEATURE_USE_FAIL = "feature.use.fail"
    HWID_MISMATCH = "security.hwid_mismatch"
    NONCE_REPLAY = "security.nonce_replay"
    RATE_LIMIT = "security.rate_limit"
    MTLS_FAIL = "security.mtls_fail"
    KEY_ROTATION = "admin.key_rotation"
    ALERT_SENT = "alert.sent"
    HEARTBEAT = "heartbeat"
    LOGOUT = "logout"
    SECURITY_EVENT = "security.client_report"


class AuditLogger:
    """Append-only structured audit logger."""

    def __init__(self, log_path: str = "./audit_log/audit.jsonl"):
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._event_counts: dict[str, int] = {}

    def log(
        self,
        event_type: AuditEventType,
        *,
        license_id: str = "",
        device_hwid: str = "",
        ip_address: str = "",
        status_code: int = 200,
        detail: Optional[dict[str, Any]] = None,
        is_alert: bool = False,
    ) -> dict:
        """
        Write an audit event.
        
        Returns the audit record dict for further processing.
        """
        now = datetime.now(timezone.utc)
        
        record = {
            "timestamp": now.isoformat(),
            "epoch": int(now.timestamp()),
            "event": event_type.value,
            "license_id": license_id,
            "device_hwid": device_hwid[:16] + "..." if len(device_hwid) > 16 else device_hwid,
            "ip": ip_address,
            "status": status_code,
            "detail": detail or {},
        }

        # Count events for alerting
        event_key = f"{event_type.value}:{ip_address}"
        self._event_counts[event_key] = self._event_counts.get(event_key, 0) + 1

        # Write to file
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error("audit_write_failed", error=str(e), path=str(self._log_path))

        # Structured log
        log_method = logger.warning if is_alert else logger.info
        if status_code >= 400:
            log_method = logger.warning
        if status_code >= 500 or is_alert:
            log_method = logger.error

        log_method(
            "audit_event",
            event_type=event_type.value,
            license_id=license_id,
            hwid=record["device_hwid"],
            ip=ip_address,
            status=status_code,
        )

        return record

    def get_failure_count(self, event_type: str, ip_address: str) -> int:
        """Get failure count for an IP/event combination."""
        key = f"{event_type}:{ip_address}"
        return self._event_counts.get(key, 0)

    def reset_counts(self) -> None:
        """Reset event counters (call periodically)."""
        self._event_counts.clear()

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Read last N audit events from file."""
        events = []
        try:
            if self._log_path.exists():
                with open(self._log_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in lines[-count:]:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except Exception as e:
            logger.error("audit_read_failed", error=str(e))
        return events
