"""
Auth Routes — Device Registration & Token Operations
======================================================
POST /auth/device-register  — Register device + get initial token
POST /auth/token/refresh     — Refresh an existing token
POST /auth/heartbeat         — Keepalive heartbeat
POST /auth/logout            — Invalidate session
"""

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_license_service
from app.licensing import LicenseService, LicenseServiceError
from app.audit import AuditLogger, AuditEventType

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------- Request / Response Schemas ----------

class DeviceRegisterRequest(BaseModel):
    license_key: str = Field(..., min_length=8, max_length=64)
    device_hwid: str = Field(..., min_length=16, max_length=128)
    fingerprint: str = Field(default="", max_length=2048)
    user_agent: str = Field(default="", max_length=256)
    product: str = Field(default="gamestore", max_length=32)

class DeviceRegisterResponse(BaseModel):
    token: str
    expires_at: int
    device_id: int
    license_plan: str
    scope: list[str]
    license_expires_at: str | None = None
    server_time: str | None = None

class TokenRefreshRequest(BaseModel):
    token: str = Field(..., min_length=32)
    device_hwid: str = Field(..., min_length=16, max_length=128)

class TokenRefreshResponse(BaseModel):
    token: str
    expires_at: int

class HeartbeatRequest(BaseModel):
    token: str = Field(..., min_length=32)
    device_hwid: str = Field(..., min_length=16, max_length=128)
    bot_status: dict | None = None  # optional bot status from client
    product: str = Field(default="", max_length=32)

class HeartbeatResponse(BaseModel):
    status: str
    server_time: int
    commands: list[dict] | None = None
    admin_message: str | None = None
    license_expires_at: str | None = None
    license_plan: str | None = None

class LogoutRequest(BaseModel):
    token: str = Field(..., min_length=32)
    device_hwid: str = Field(..., min_length=16, max_length=128)


# ---------- Route Handlers ----------

@router.post("/device-register", response_model=DeviceRegisterResponse)
async def device_register(
    body: DeviceRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: LicenseService = Depends(get_license_service),
):
    """
    Register a device to a license and receive an Ed25519-signed token.
    The token is bound to the HWID and carries scope claims.
    Also starts an online session for tracking.
    """
    from datetime import datetime, timezone
    from app.models import OnlineSession

    client_ip = request.client.host if request.client else "unknown"
    try:
        result = await svc.register_device(
            db=db,
            license_key=body.license_key,
            device_hwid=body.device_hwid,
            ip_address=client_ip,
            user_agent=body.user_agent,
            fingerprint=body.fingerprint,
            product=body.product,
        )

        # Start online session for session tracking
        if "device_id" in result:
            # Get license_id from the token payload (sub field)
            try:
                payload = svc._engine.verify_token(result["token"])
                lic_id = int(payload.sub) if payload.sub.isdigit() else None
                if lic_id:
                    session_record = OnlineSession(
                        license_id=lic_id,
                        device_hwid=body.device_hwid,
                        ip_address=client_ip,
                    )
                    db.add(session_record)
                    await db.commit()
            except Exception:
                pass  # session tracking is best-effort

        return DeviceRegisterResponse(**result)
    except LicenseServiceError as e:
        return JSONResponse(
            status_code=e.status,
            content={"error": e.code, "message": e.message},
        )


@router.post("/token/refresh", response_model=TokenRefreshResponse)
async def token_refresh(
    body: TokenRefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: LicenseService = Depends(get_license_service),
):
    """
    Refresh an existing (or recently-expired) token.
    Returns a new token with a fresh TTL.
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        result = await svc.refresh_token(
            db=db,
            current_token=body.token,
            device_hwid=body.device_hwid,
            ip_address=client_ip,
        )
        return TokenRefreshResponse(**result)
    except LicenseServiceError as e:
        return JSONResponse(
            status_code=e.status,
            content={"error": e.code, "message": e.message},
        )


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    body: HeartbeatRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: LicenseService = Depends(get_license_service),
):
    """
    Keepalive heartbeat — verifies certificate + token validity.
    Updates last_seen_at on License and Device for online tracking.
    Accepts optional bot_status and returns pending admin commands.
    Does not issue a new token.
    """
    import time
    from datetime import datetime, timezone
    from sqlalchemy import select
    from app.models import License, Device, BotStatus, AdminCommandQueue

    client_ip = request.client.host if request.client else "unknown"
    try:
        payload = svc._engine.verify_token(body.token)
        if payload.hwid != body.device_hwid:
            return JSONResponse(status_code=403, content={"error": "HWID_MISMATCH"})

        # Update last_seen_at on License and Device
        now = datetime.now(timezone.utc)
        lic_id = int(payload.sub) if payload.sub.isdigit() else None
        lic = None
        if lic_id:
            result = await db.execute(select(License).where(License.id == lic_id))
            lic = result.scalar_one_or_none()

        # Fallback: if license not found by ID (e.g. after DB migration),
        # find it via device HWID binding
        if not lic:
            result = await db.execute(
                select(Device).where(Device.device_hwid == body.device_hwid, Device.is_active == True)
            )
            device_rec = result.scalar_one_or_none()
            if device_rec:
                result = await db.execute(select(License).where(License.id == device_rec.license_id))
                lic = result.scalar_one_or_none()

        if not lic:
            return JSONResponse(status_code=401, content={"error": "LICENSE_NOT_FOUND", "message": "License not found"})

        if lic.is_revoked or not lic.is_active:
            return JSONResponse(status_code=403, content={"error": "LICENSE_REVOKED", "message": "License revoked"})

        expires = lic.expires_at
        if expires is not None:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires < now:
                return JSONResponse(status_code=403, content={"error": "LICENSE_EXPIRED", "message": "License expired"})

        requested_product = body.product.strip().lower()
        if requested_product:
            bound_product = (lic.product or "gamestore").strip().lower() or "gamestore"
            if requested_product != bound_product:
                return JSONResponse(status_code=403, content={"error": "PRODUCT_MISMATCH", "message": "Wrong product"})

        if lic:
            lic.last_seen_at = now
            lic.last_ip = client_ip

        # Update device
        if lic:
            result = await db.execute(
                select(Device).where(
                    Device.license_id == lic.id,
                    Device.device_hwid == body.device_hwid,
                )
            )
            device = result.scalar_one_or_none()
            if device:
                device.last_seen_at = now
                device.last_ip = client_ip

        # --- Save bot_status if provided ---
        if body.bot_status and lic:
            bs = body.bot_status
            result = await db.execute(
                select(BotStatus).where(BotStatus.device_hwid == body.device_hwid)
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.license_id = lic.id
                existing.bot_running = bs.get("running", False)
                existing.game_connected = bs.get("game_connected", False)
                existing.character_name = bs.get("character_name", "")
                existing.bot_state = bs.get("state", "idle")
                existing.mobs_killed = bs.get("mobs_killed", 0)
                existing.items_collected = bs.get("items_collected", 0)
                existing.death_count = bs.get("death_count", 0)
                existing.potions_used = bs.get("potions_used", 0)
                existing.uptime_seconds = bs.get("uptime_seconds", 0)
                existing.hp = bs.get("hp", 0)
                existing.max_hp = bs.get("max_hp", 0)
                existing.mp = bs.get("mp", 0)
                existing.max_mp = bs.get("max_mp", 0)
                existing.pos_x = bs.get("pos_x", 0)
                existing.pos_y = bs.get("pos_y", 0)
                existing.last_updated = now
            else:
                new_status = BotStatus(
                    license_id=lic.id,
                    device_hwid=body.device_hwid,
                    bot_running=bs.get("running", False),
                    game_connected=bs.get("game_connected", False),
                    character_name=bs.get("character_name", ""),
                    bot_state=bs.get("state", "idle"),
                    mobs_killed=bs.get("mobs_killed", 0),
                    items_collected=bs.get("items_collected", 0),
                    death_count=bs.get("death_count", 0),
                    potions_used=bs.get("potions_used", 0),
                    uptime_seconds=bs.get("uptime_seconds", 0),
                    hp=bs.get("hp", 0),
                    max_hp=bs.get("max_hp", 0),
                    mp=bs.get("mp", 0),
                    max_mp=bs.get("max_mp", 0),
                    pos_x=bs.get("pos_x", 0),
                    pos_y=bs.get("pos_y", 0),
                    last_updated=now,
                )
                db.add(new_status)

        # --- Fetch pending admin commands ---
        pending_commands = []
        admin_message = None
        result = await db.execute(
            select(AdminCommandQueue).where(
                AdminCommandQueue.device_hwid == body.device_hwid,
                AdminCommandQueue.delivered == False,
            ).order_by(AdminCommandQueue.created_at)
        )
        commands = result.scalars().all()
        for cmd in commands:
            if cmd.action == "show_message" and cmd.param:
                admin_message = cmd.param
            else:
                pending_commands.append({
                    "action": cmd.action,
                    "param": cmd.param or "",
                    "signature": cmd.signature or "",
                })
            cmd.delivered = True
            cmd.delivered_at = now

        await db.commit()

        svc._audit.log(
            AuditEventType.HEARTBEAT,
            license_id=payload.sub,
            device_hwid=body.device_hwid,
            ip_address=client_ip,
        )
        license_expires = None
        if lic.expires_at is not None:
            exp = lic.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            license_expires = exp.isoformat()
        return HeartbeatResponse(
            status="ok",
            server_time=int(time.time()),
            commands=pending_commands if pending_commands else None,
            admin_message=admin_message,
            license_expires_at=license_expires,
            license_plan=lic.plan,
        )
    except (ValueError, PermissionError):
        return JSONResponse(status_code=401, content={"error": "INVALID_TOKEN"})


@router.post("/logout")
async def logout(
    body: LogoutRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: LicenseService = Depends(get_license_service),
):
    """
    Invalidate session. Nonce is blacklisted to prevent token reuse.
    Also clears last_seen_at so user immediately appears offline.
    Ends active online session and clears bot status.
    """
    import logging
    from datetime import datetime, timezone
    from sqlalchemy import select, delete as sa_delete
    from app.models import License, Device, OnlineSession, BotStatus

    logger = logging.getLogger("auth.logout")
    client_ip = request.client.host if request.client else "unknown"

    # Step 1: Verify token and extract license info
    payload = None
    try:
        payload = svc._engine.verify_token(body.token)
        await svc._nonce.mark_used(payload.nonce, 600)
    except Exception as e:
        logger.warning("Token verification failed during logout: %s", e)

    # Step 2: Clear last_seen_at + end session
    if payload and payload.sub and payload.sub.isdigit():
        lic_id = int(payload.sub)
        try:
            now = datetime.now(timezone.utc)

            result = await db.execute(select(License).where(License.id == lic_id))
            lic = result.scalar_one_or_none()

            # Fallback: find license via device HWID if ID mismatch (DB migration)
            if not lic:
                result = await db.execute(
                    select(Device).where(Device.device_hwid == body.device_hwid, Device.is_active == True)
                )
                device_rec = result.scalar_one_or_none()
                if device_rec:
                    result = await db.execute(select(License).where(License.id == device_rec.license_id))
                    lic = result.scalar_one_or_none()

            if lic:
                lic.last_seen_at = None
                logger.info("Cleared last_seen_at for license %d", lic.id)

            result = await db.execute(
                select(Device).where(
                    Device.license_id == lic.id if lic else Device.license_id == lic_id,
                    Device.device_hwid == body.device_hwid,
                )
            )
            device = result.scalar_one_or_none()
            if device:
                device.last_seen_at = None
                logger.info("Cleared last_seen_at for device %s", body.device_hwid[:12])

            # End active online session
            actual_lic_id = lic.id if lic else lic_id
            result = await db.execute(
                select(OnlineSession).where(
                    OnlineSession.license_id == actual_lic_id,
                    OnlineSession.device_hwid == body.device_hwid,
                    OnlineSession.ended_at == None,
                ).order_by(OnlineSession.started_at.desc())
            )
            active_session = result.scalar_one_or_none()
            if active_session:
                active_session.ended_at = now
                elapsed = (now - active_session.started_at).total_seconds()
                active_session.duration_seconds = int(elapsed)
                logger.info("Ended session %d (duration=%ds)", active_session.id, int(elapsed))

            # Clear bot status
            await db.execute(
                sa_delete(BotStatus).where(BotStatus.device_hwid == body.device_hwid)
            )

            await db.commit()
            logger.info("Logout DB commit successful for license %d", lic_id)
        except Exception as e:
            logger.error("Failed to clear last_seen_at during logout: %s", e)
            try:
                await db.rollback()
            except Exception:
                pass

    # Step 3: Audit logging
    if payload:
        try:
            svc._audit.log(
                AuditEventType.LOGOUT,
                license_id=payload.sub,
                device_hwid=body.device_hwid,
                ip_address=client_ip,
            )
        except Exception as e:
            logger.warning("Audit log failed during logout: %s", e)

    return {"status": "logged_out"}


# ---------- Tamper / Anti-Debug Report ----------

class TamperReportRequest(BaseModel):
    device_hwid: str = Field(..., min_length=8, max_length=128)
    threat_type: str = Field(..., min_length=1, max_length=64)
    detail: str = Field(default="", max_length=512)
    timestamp: int = Field(default=0)
    token: str = Field(default="", max_length=4096)


@router.post("/tamper-report")
async def tamper_report(
    body: TamperReportRequest,
    request: Request,
    svc: LicenseService = Depends(get_license_service),
):
    """
    Receive tamper/anti-debug reports from clients.
    
    Best-effort: always returns 200 to avoid revealing detection to attacker.
    The audit log records the event for investigation.
    """
    client_ip = request.client.host if request.client else "unknown"
    license_id = ""

    # Try to extract license from token (if provided)
    if body.token:
        try:
            payload = svc._engine.verify_token(body.token)
            license_id = payload.sub
        except Exception:
            pass

    svc._audit.log(
        AuditEventType.SECURITY_EVENT,
        license_id=license_id,
        device_hwid=body.device_hwid,
        ip_address=client_ip,
        extra={
            "threat_type": body.threat_type,
            "detail": body.detail,
            "client_ts": body.timestamp,
        },
    )

    # Always return success (don't leak detection status)
    return {"status": "received"}
