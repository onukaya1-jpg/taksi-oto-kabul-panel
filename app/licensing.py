"""
Licensing Service — Business Logic Layer
==========================================
Handles license validation, device registration, and token issuance.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import structlog

from app.models import License, Device, TokenLog, SecurityEvent
from app.token_engine import TokenEngine, TokenPayload
from app.nonce_store import NonceStore
from app.audit import AuditLogger, AuditEventType

logger = structlog.get_logger(__name__)


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Make naive datetimes UTC-aware (SQLite strips timezone info)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class LicenseServiceError(Exception):
    """Base exception for license service errors."""

    def __init__(self, message: str, code: str = "UNKNOWN", status: int = 400):
        self.message = message
        self.code = code
        self.status = status
        super().__init__(message)


class LicenseService:
    """
    Core service: license validation, device binding, token issuance.
    """

    def __init__(
        self,
        token_engine: TokenEngine,
        nonce_store: NonceStore,
        audit: AuditLogger,
    ):
        self._engine = token_engine
        self._nonce = nonce_store
        self._audit = audit

    # ----------------------------------------------------------------
    # Device Registration
    # ----------------------------------------------------------------

    async def register_device(
        self,
        db: AsyncSession,
        license_key: str,
        device_hwid: str,
        ip_address: str = "",
        user_agent: str = "",
        fingerprint: str = "",
        product: str = "gamestore",
    ) -> dict:
        """
        Register a device to a license.

        Steps:
          1. Validate license exists, is active, not revoked, not expired
          2. Check HWID binding (single device or multi-device)
          3. Create device record if new
          4. Issue initial token

        Returns:
            {token, expires_at, device_id, license_plan}
        """
        # Step 1: Find license
        stmt = select(License).where(License.license_key == license_key)
        result = await db.execute(stmt)
        lic = result.scalar_one_or_none()

        if not lic:
            self._audit.log(
                AuditEventType.DEVICE_REGISTER_FAIL,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=404,
                detail={"reason": "license_not_found", "key_prefix": license_key[:8]},
            )
            raise LicenseServiceError("License not found", "LICENSE_NOT_FOUND", 404)

        if lic.is_revoked:
            self._audit.log(
                AuditEventType.DEVICE_REGISTER_FAIL,
                license_id=str(lic.id),
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"reason": "license_revoked"},
            )
            raise LicenseServiceError("License revoked", "LICENSE_REVOKED", 403)

        if not lic.is_active:
            self._audit.log(
                AuditEventType.DEVICE_REGISTER_FAIL,
                license_id=str(lic.id),
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"reason": "license_inactive"},
            )
            raise LicenseServiceError("License inactive", "LICENSE_INACTIVE", 403)

        requested_product = (product or "gamestore").strip().lower() or "gamestore"
        bound_product = (lic.product or "gamestore").strip().lower() or "gamestore"
        if requested_product != bound_product:
            self._audit.log(
                AuditEventType.DEVICE_REGISTER_FAIL,
                license_id=str(lic.id),
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"reason": "product_mismatch", "bound": bound_product, "requested": requested_product},
            )
            raise LicenseServiceError("License belongs to another product", "PRODUCT_MISMATCH", 403)

        # --- Lazy-start expiry: set expires_at on first activation ---
        _now_utc = datetime.now(timezone.utc)
        if lic.activated_at is None:
            # First-ever use of this key — start the timer now
            lic.activated_at = _now_utc
            if lic.duration_minutes and not lic.expires_at:
                # Sub-day plan (hourly/minute): use minutes
                lic.expires_at = _now_utc + timedelta(minutes=lic.duration_minutes)
                logger.info("license_activated", key=lic.license_key[:8],
                            duration_minutes=lic.duration_minutes, expires=lic.expires_at.isoformat())
            elif lic.duration_days and not lic.expires_at:
                lic.expires_at = _now_utc + timedelta(days=lic.duration_days)
                logger.info("license_activated", key=lic.license_key[:8],
                            duration=lic.duration_days, expires=lic.expires_at.isoformat())

        if lic.expires_at and _ensure_utc(lic.expires_at) < _now_utc:
            self._audit.log(
                AuditEventType.DEVICE_REGISTER_FAIL,
                license_id=str(lic.id),
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"reason": "license_expired"},
            )
            raise LicenseServiceError("License expired", "LICENSE_EXPIRED", 403)

        # Step 2: HWID binding check
        if lic.hwid and lic.hwid != device_hwid:
            # Already bound to different HWID
            self._audit.log(
                AuditEventType.HWID_MISMATCH,
                license_id=str(lic.id),
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"bound_hwid_prefix": lic.hwid[:8], "attempt_hwid_prefix": device_hwid[:8]},
                is_alert=True,
            )
            # Record security event
            db.add(SecurityEvent(
                event_type="hwid_mismatch",
                device_hwid=device_hwid,
                ip_address=ip_address,
                detail=f"License {lic.id} bound to {lic.hwid[:8]}..., attempt from {device_hwid[:8]}...",
                severity="warning",
            ))
            raise LicenseServiceError("Device HWID mismatch", "HWID_MISMATCH", 403)

        # Step 3: Check/create device record
        stmt = select(Device).where(
            Device.license_id == lic.id,
            Device.device_hwid == device_hwid,
        )
        result = await db.execute(stmt)
        device = result.scalar_one_or_none()

        if not device:
            # Check max devices
            stmt = select(Device).where(
                Device.license_id == lic.id,
                Device.is_active == True,
            )
            result = await db.execute(stmt)
            active_devices = result.scalars().all()

            if len(active_devices) >= lic.max_devices:
                self._audit.log(
                    AuditEventType.DEVICE_REGISTER_FAIL,
                    license_id=str(lic.id),
                    device_hwid=device_hwid,
                    ip_address=ip_address,
                    status_code=403,
                    detail={"reason": "max_devices_reached", "current": len(active_devices), "max": lic.max_devices},
                )
                raise LicenseServiceError("Max devices reached", "MAX_DEVICES", 403)

            # Create new device
            device = Device(
                license_id=lic.id,
                device_hwid=device_hwid,
                device_fingerprint=fingerprint,
                last_ip=ip_address,
                user_agent=user_agent,
                is_active=True,
            )
            db.add(device)

            # Bind HWID to license (first device)
            if not lic.hwid:
                lic.hwid = device_hwid

        # Update last seen (tz-aware UTC)
        _now = datetime.now(timezone.utc)
        device.last_seen_at = _now
        device.last_ip = ip_address
        lic.last_seen_at = _now
        lic.last_ip = ip_address

        await db.flush()

        # Step 4: Issue token
        scope = self._scope_for_plan(lic.plan)
        token, payload = self._engine.create_token(
            license_id=str(lic.id),
            device_hwid=device_hwid,
            scope=scope,
        )

        # Log token issuance
        db.add(TokenLog(
            license_id=lic.id,
            device_hwid=device_hwid,
            token_nonce=payload.nonce,
            action="issue",
            ip_address=ip_address,
            expires_at=datetime.fromtimestamp(payload.exp, tz=timezone.utc),
        ))
        await self._nonce.mark_used(payload.nonce, payload.exp - payload.iat + 60)

        self._audit.log(
            AuditEventType.DEVICE_REGISTER,
            license_id=str(lic.id),
            device_hwid=device_hwid,
            ip_address=ip_address,
            detail={"device_id": device.id, "plan": lic.plan},
        )

        return {
            "token": token,
            "expires_at": payload.exp,
            "device_id": device.id,
            "license_plan": lic.plan,
            "scope": scope,
            "license_expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "customer_name": lic.customer_name or "",
            "server_time": datetime.now(timezone.utc).isoformat(),
        }

    # ----------------------------------------------------------------
    # Token Refresh
    # ----------------------------------------------------------------

    async def refresh_token(
        self,
        db: AsyncSession,
        current_token: str,
        device_hwid: str,
        ip_address: str = "",
    ) -> dict:
        """
        Refresh a valid (or recently expired) token.

        Returns:
            {token, expires_at}
        """
        try:
            payload = self._engine.verify_token(current_token)
        except PermissionError:
            # Allow refresh of recently expired tokens (grace period: 60s)
            try:
                parts = current_token.split(".", 1)
                if len(parts) != 2:
                    raise ValueError("bad format")
                import base64
                import json
                raw = base64.urlsafe_b64decode(parts[1])
                d = json.loads(raw)
                from app.token_engine import TokenPayload as TP
                payload = TP.from_dict(d)
                import time
                if payload.exp + 60 < int(time.time()):
                    raise PermissionError("Token too old for refresh")
            except PermissionError:
                raise
            except Exception:
                raise LicenseServiceError("Invalid token for refresh", "INVALID_TOKEN", 401)
        except ValueError as e:
            self._audit.log(
                AuditEventType.TOKEN_REFRESH_FAIL,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=401,
                detail={"reason": str(e)},
            )
            raise LicenseServiceError("Invalid token", "INVALID_TOKEN", 401)

        # Verify HWID matches
        if payload.hwid != device_hwid:
            self._audit.log(
                AuditEventType.HWID_MISMATCH,
                license_id=payload.sub,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"token_hwid_prefix": payload.hwid[:8], "request_hwid_prefix": device_hwid[:8]},
                is_alert=True,
            )
            raise LicenseServiceError("HWID mismatch", "HWID_MISMATCH", 403)

        # Verify license still active + update last_seen
        lic_id = int(payload.sub) if payload.sub.isdigit() else None
        if lic_id:
            stmt = select(License).where(License.id == lic_id)
            result = await db.execute(stmt)
            lic = result.scalar_one_or_none()
            if not lic or not lic.is_active or lic.is_revoked:
                raise LicenseServiceError("License no longer valid", "LICENSE_INVALID", 403)
            # Update last_seen on refresh (naive UTC for SQLite compatibility)
            lic.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
            lic.last_ip = ip_address
            # Also update device
            dev_stmt = select(Device).where(
                Device.license_id == lic_id,
                Device.device_hwid == device_hwid,
            )
            dev_result = await db.execute(dev_stmt)
            dev = dev_result.scalar_one_or_none()
            if dev:
                dev.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
                dev.last_ip = ip_address

        # Issue new token
        new_token, new_payload = self._engine.create_token(
            license_id=payload.sub,
            device_hwid=device_hwid,
            scope=payload.scope,
        )

        db.add(TokenLog(
            license_id=lic_id,
            device_hwid=device_hwid,
            token_nonce=new_payload.nonce,
            action="refresh",
            ip_address=ip_address,
            expires_at=datetime.fromtimestamp(new_payload.exp, tz=timezone.utc),
        ))
        await self._nonce.mark_used(new_payload.nonce, new_payload.exp - new_payload.iat + 60)

        self._audit.log(
            AuditEventType.TOKEN_REFRESH,
            license_id=payload.sub,
            device_hwid=device_hwid,
            ip_address=ip_address,
        )

        return {
            "token": new_token,
            "expires_at": new_payload.exp,
        }

    # ----------------------------------------------------------------
    # Feature Use (Token Verification)
    # ----------------------------------------------------------------

    async def verify_feature_use(
        self,
        db: AsyncSession,
        token: str,
        feature: str,
        device_hwid: str,
        nonce: str,
        ip_address: str = "",
    ) -> dict:
        """
        Verify a token for feature access.

        Steps:
          1. Verify token signature + expiry
          2. Check HWID match
          3. Check nonce replay
          4. Check scope permissions
          5. Log usage

        Returns:
            {allowed: bool, payload, remaining_ttl}
        """
        # Nonce replay check
        if await self._nonce.is_used(nonce):
            self._audit.log(
                AuditEventType.NONCE_REPLAY,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"nonce_prefix": nonce[:8]},
                is_alert=True,
            )
            db.add(SecurityEvent(
                event_type="nonce_replay",
                device_hwid=device_hwid,
                ip_address=ip_address,
                detail=f"Replay attempt with nonce {nonce[:8]}...",
                severity="critical",
            ))
            raise LicenseServiceError("Nonce replay detected", "NONCE_REPLAY", 403)

        # Mark nonce as used
        await self._nonce.mark_used(nonce, 600)

        # Verify token
        try:
            payload = self._engine.verify_token(token)
        except ValueError as e:
            self._audit.log(
                AuditEventType.TOKEN_VERIFY_FAIL,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=401,
                detail={"reason": str(e)},
            )
            raise LicenseServiceError("Invalid token", "INVALID_TOKEN", 401)
        except PermissionError:
            self._audit.log(
                AuditEventType.TOKEN_VERIFY_FAIL,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=401,
                detail={"reason": "token_expired"},
            )
            raise LicenseServiceError("Token expired", "TOKEN_EXPIRED", 401)

        # HWID match
        if payload.hwid != device_hwid:
            self._audit.log(
                AuditEventType.HWID_MISMATCH,
                license_id=payload.sub,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"token_hwid_prefix": payload.hwid[:8]},
                is_alert=True,
            )
            raise LicenseServiceError("HWID mismatch", "HWID_MISMATCH", 403)

        # Scope check
        required_scope = f"feature:{feature}"
        if required_scope not in payload.scope and "feature:*" not in payload.scope:
            self._audit.log(
                AuditEventType.FEATURE_USE_FAIL,
                license_id=payload.sub,
                device_hwid=device_hwid,
                ip_address=ip_address,
                status_code=403,
                detail={"feature": feature, "scope": payload.scope},
            )
            raise LicenseServiceError(f"Feature '{feature}' not in scope", "SCOPE_DENIED", 403)

        import time
        remaining_ttl = payload.exp - int(time.time())

        # Log usage
        db.add(TokenLog(
            license_id=int(payload.sub) if payload.sub.isdigit() else None,
            device_hwid=device_hwid,
            token_nonce=nonce,
            action="verify",
            ip_address=ip_address,
        ))

        self._audit.log(
            AuditEventType.FEATURE_USE,
            license_id=payload.sub,
            device_hwid=device_hwid,
            ip_address=ip_address,
            detail={"feature": feature, "remaining_ttl": remaining_ttl},
        )

        return {
            "allowed": True,
            "license_id": payload.sub,
            "scope": payload.scope,
            "remaining_ttl": remaining_ttl,
        }

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _scope_for_plan(plan: str) -> list[str]:
        """Map plan to scopes.
        Tüm planlar tam erişim alır (daily/weekly/monthly/custom/lifetime).
        Fark sadece sürede.
        """
        full_access = ["feature:use", "feature:farm", "feature:offset_read", "offset:read", "offset:write", "stat:read"]
        scopes = {
            "hourly": full_access,
            "minute": full_access,
            "daily": full_access,
            "weekly": full_access,
            "monthly": full_access,
            "custom": full_access,
            "lifetime": full_access,
            "admin": ["feature:*", "offset:*", "stat:*", "admin:*"],
        }
        return scopes.get(plan, full_access)
