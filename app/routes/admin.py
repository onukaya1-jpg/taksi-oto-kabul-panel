"""
Admin Routes — License Management API
=======================================
Protected by ADMIN_API_KEY header.
Used by the developer to create/manage licenses for customers.

POST   /admin/licenses              — Create new license
GET    /admin/licenses              — List all licenses
GET    /admin/licenses/{license_id} — Get license details
POST   /admin/licenses/{license_id}/revoke  — Revoke a license
POST   /admin/licenses/{license_id}/reset-hwid — Reset HWID binding
DELETE /admin/licenses/{license_id} — Delete a license
GET    /admin/stats                 — Dashboard statistics
POST   /admin/licenses/{license_id}/extend — Extend expiry
POST   /admin/devices/{device_hwid}/ban    — Ban a device
"""

import secrets
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, Request, HTTPException, Header
from fastapi.responses import JSONResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, delete

from app.database import get_db
from app.models import License, Device, TokenLog, SecurityEvent
from app.settings import get_settings
from app.license_backup import backup_licenses_to_github

router = APIRouter(prefix="/admin", tags=["admin"])


async def _auto_backup(db: AsyncSession):
    """Fire-and-forget backup after license changes. Never raises."""
    try:
        await backup_licenses_to_github(db)
    except Exception:
        pass  # logged inside backup function


def _make_aware(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware UTC (handles both SQLite naive and PostgreSQL aware)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

# ---------- Admin Panel UI ----------

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
async def admin_panel():
    """Serve the admin panel single-page application."""
    html_path = _STATIC_DIR / "admin.html"
    if not html_path.exists():
        raise HTTPException(404, "Admin panel not found")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


# ---------- API Key Auth ----------

async def verify_admin_key(x_admin_key: str = Header(..., alias="X-Admin-Key")):
    """Verify admin API key from header."""
    settings = get_settings()
    expected = settings.ADMIN_API_KEY
    if not expected:
        raise HTTPException(503, "Admin API not configured — set ADMIN_API_KEY")
    if not secrets.compare_digest(x_admin_key, expected):
        raise HTTPException(403, "Invalid admin API key")
    return True


# ---------- Schemas ----------

# Plan → varsayılan gün eşleştirmesi
PLAN_DEFAULT_DAYS = {
    "daily": 1,
    "weekly": 7,
    "monthly": 30,
    "custom": 30,     # özel süre, days parametresiyle belirlenir
    "lifetime": 36500, # ~100 yıl
    "admin": 36500,
}

# Plan → varsayılan dakika eşleştirmesi (sub-day planlar)
PLAN_DEFAULT_MINUTES = {
    "hourly": 60,     # 1 saat
    "minute": 30,     # 30 dakika
}

# Sub-day planlar mı?
SUB_DAY_PLANS = {"hourly", "minute"}

class CreateLicenseRequest(BaseModel):
    plan: str = Field(default="monthly", pattern="^(hourly|minute|daily|weekly|monthly|custom|lifetime|admin)$")
    days: Optional[int] = Field(default=None, ge=1, le=36500)  # None = plan varsayılanı kullanılır
    hours: Optional[int] = Field(default=None, ge=1, le=8760)  # Saatlik planlar için
    minutes: Optional[int] = Field(default=None, ge=1, le=525600)  # Dakikalık planlar için
    max_devices: int = Field(default=1, ge=1, le=1)  # Always 1 device per key
    notes: str = Field(default="", max_length=500)
    customer_name: str = Field(default="", max_length=200)
    license_key: str = Field(default="", max_length=19)  # Optional: custom key (XXXX-XXXX-XXXX-XXXX)
    product: str = Field(default="taksi", pattern="^(gamestore|taksi)$")


class CreateLicenseResponse(BaseModel):
    license_key: str
    plan: str
    product: str = "gamestore"
    expires_at: str
    max_devices: int
    created_at: str


class LicenseDetail(BaseModel):
    id: int
    license_key: str
    plan: str
    product: str = "gamestore"
    hwid: Optional[str] = None
    is_active: bool
    is_revoked: bool
    created_at: Optional[str] = None
    activated_at: Optional[str] = None
    expires_at: Optional[str] = None
    duration_days: Optional[int] = None
    duration_minutes: Optional[int] = None
    last_seen_at: Optional[str] = None
    last_ip: Optional[str] = None
    max_devices: int
    notes: Optional[str] = None
    devices: list[dict] = []


class ExtendRequest(BaseModel):
    days: int = Field(..., ge=1, le=3650)


class StatsResponse(BaseModel):
    total_licenses: int
    active_licenses: int
    expired_licenses: int
    revoked_licenses: int
    unused_licenses: int = 0
    online_now: int = 0
    total_devices: int
    active_devices: int
    security_events_24h: int
    token_ops_24h: int


# ---------- License Key Generator ----------

def generate_license_key() -> str:
    """Generate a human-readable license key: XXXX-XXXX-XXXX-XXXX."""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # No I/O/0/1 (ambiguous)
    segments = []
    for _ in range(4):
        segment = "".join(secrets.choice(chars) for _ in range(4))
        segments.append(segment)
    return "-".join(segments)


# ---------- Route Handlers ----------

@router.post("/licenses", response_model=CreateLicenseResponse)
async def create_license(
    body: CreateLicenseRequest,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Create a new license key for a customer."""
    # Use custom key if provided, otherwise generate
    if body.license_key:
        key = body.license_key.strip().upper()
        exists = await db.execute(
            select(License).where(License.license_key == key)
        )
        if exists.scalar_one_or_none():
            raise HTTPException(409, f"License key already exists: {key}")
    else:
        for _ in range(10):
            key = generate_license_key()
            exists = await db.execute(
                select(License).where(License.license_key == key)
            )
            if not exists.scalar_one_or_none():
                break
        else:
            raise HTTPException(500, "Failed to generate unique key")

    now = datetime.now(timezone.utc)

    # Sub-day planlar için dakika, diğerleri için gün hesapla
    actual_days = None
    actual_minutes = None

    if body.plan in SUB_DAY_PLANS:
        # Saatlik veya dakikalık plan
        if body.plan == "hourly":
            actual_minutes = (body.hours * 60) if body.hours else (body.minutes if body.minutes else PLAN_DEFAULT_MINUTES["hourly"])
        else:  # minute
            actual_minutes = body.minutes if body.minutes else PLAN_DEFAULT_MINUTES["minute"]
    else:
        # Gün bazlı plan
        actual_days = body.days if body.days is not None else PLAN_DEFAULT_DAYS.get(body.plan, 30)

    # expires_at left NULL — timer starts on first activation
    lic = License(
        license_key=key,
        plan=body.plan,
        product=body.product,
        is_active=True,
        is_revoked=False,
        created_at=now,
        expires_at=None,
        duration_days=actual_days,
        duration_minutes=actual_minutes,
        max_devices=body.max_devices,
        notes=f"{body.customer_name}: {body.notes}" if body.customer_name else body.notes,
    )
    db.add(lic)
    await db.flush()

    # Auto-backup to GitHub
    await _auto_backup(db)

    # Süre açıklaması
    if body.plan == "lifetime":
        expires_text = "Lifetime (sınırsız)"
    elif body.plan in SUB_DAY_PLANS:
        if actual_minutes >= 60:
            h = actual_minutes // 60
            m = actual_minutes % 60
            time_str = f"{h} saat" + (f" {m} dk" if m else "")
        else:
            time_str = f"{actual_minutes} dakika"
        expires_text = f"İlk kullanımda aktif olur ({time_str})"
    else:
        expires_text = f"İlk kullanımda aktif olur ({actual_days} gün)"

    return CreateLicenseResponse(
        license_key=key,
        plan=body.plan,
        product=body.product,
        expires_at=expires_text,
        max_devices=body.max_devices,
        created_at=now.isoformat(),
    )


@router.get("/licenses")
async def list_licenses(
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
    active_only: bool = False,
    plan: str = "",
    product: str = "",
    search: str = "",
    page: int = 1,
    per_page: int = 50,
):
    """List all licenses with optional filtering. Online users sorted to top."""
    from sqlalchemy import case, or_

    online_cutoff = datetime.now(timezone.utc) - timedelta(minutes=2)

    # Sort: online first (desc so True=1 comes first), then created_at desc
    is_online_expr = case(
        (License.last_seen_at >= online_cutoff, 1),
        else_=0,
    )
    query = select(License).order_by(is_online_expr.desc(), License.created_at.desc())

    if active_only:
        query = query.where(License.is_active == True, License.is_revoked == False)
    if plan:
        query = query.where(License.plan == plan)
    if product:
        query = query.where(License.product == product)
    if search:
        term = f"%{search}%"
        query = query.where(
            or_(
                License.license_key.ilike(term),
                License.hwid.ilike(term),
                License.notes.ilike(term),
            )
        )

    # Pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    licenses = result.scalars().all()

    # Count total (with same filters)
    count_q = select(func.count(License.id))
    if active_only:
        count_q = count_q.where(License.is_active == True, License.is_revoked == False)
    if plan:
        count_q = count_q.where(License.plan == plan)
    if product:
        count_q = count_q.where(License.product == product)
    if search:
        term = f"%{search}%"
        count_q = count_q.where(
            or_(
                License.license_key.ilike(term),
                License.hwid.ilike(term),
                License.notes.ilike(term),
            )
        )
    total = (await db.execute(count_q)).scalar() or 0

    return {
        "licenses": [
            {
                "id": lic.id,
                "license_key": lic.license_key,
                "plan": lic.plan,
                "product": lic.product or "gamestore",
                "is_active": lic.is_active,
                "is_revoked": lic.is_revoked,
                "hwid": lic.hwid[:12] + "..." if lic.hwid else None,
                "created_at": lic.created_at.isoformat() if lic.created_at else None,
                "activated_at": lic.activated_at.isoformat() if lic.activated_at else None,
                "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
                "duration_days": lic.duration_days,
                "duration_minutes": lic.duration_minutes,
                "last_seen_at": lic.last_seen_at.isoformat() if lic.last_seen_at else None,
                "last_ip": lic.last_ip,
                "max_devices": lic.max_devices,
                "is_online": bool(
                    lic.is_active and not lic.is_revoked
                    and lic.last_seen_at
                    and _make_aware(lic.last_seen_at) >= online_cutoff
                ),
            }
            for lic in licenses
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


# ---------- Export (Backup) — MUST be before /{license_id} ----------

@router.get("/licenses/export")
async def export_licenses(
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Export ALL licenses as JSON for backup/restore.
    Use this to back up keys before redeployment.
    The output can be POSTed to /admin/import to restore.
    """
    result = await db.execute(
        select(License).order_by(License.id)
    )
    licenses = result.scalars().all()

    exported = []
    for lic in licenses:
        exported.append({
            "key": lic.license_key,
            "plan": lic.plan,
            "product": lic.product or "gamestore",
            "is_active": lic.is_active,
            "is_revoked": lic.is_revoked,
            "hwid": lic.hwid,
            "created_at": lic.created_at.isoformat() if lic.created_at else None,
            "activated_at": lic.activated_at.isoformat() if lic.activated_at else None,
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "duration_days": lic.duration_days,
            "duration_minutes": lic.duration_minutes,
            "last_seen": lic.last_seen_at.isoformat() if lic.last_seen_at else None,
            "last_ip": lic.last_ip,
            "max_devices": lic.max_devices,
            "notes": lic.notes or "",
        })

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total": len(exported),
        "keys": exported,
    }


@router.get("/licenses/{license_id}", response_model=LicenseDetail)
async def get_license(
    license_id: int,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed info for a specific license."""
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    # Get devices
    dev_result = await db.execute(
        select(Device).where(Device.license_id == lic.id)
    )
    devices = dev_result.scalars().all()

    return LicenseDetail(
        id=lic.id,
        license_key=lic.license_key,
        plan=lic.plan,
        product=lic.product or "gamestore",
        hwid=lic.hwid,
        is_active=lic.is_active,
        is_revoked=lic.is_revoked,
        created_at=lic.created_at.isoformat() if lic.created_at else None,
        activated_at=lic.activated_at.isoformat() if lic.activated_at else None,
        expires_at=lic.expires_at.isoformat() if lic.expires_at else None,
        duration_days=lic.duration_days,
        duration_minutes=lic.duration_minutes,
        last_seen_at=lic.last_seen_at.isoformat() if lic.last_seen_at else None,
        last_ip=lic.last_ip,
        max_devices=lic.max_devices,
        notes=lic.notes,
        devices=[
            {
                "id": d.id,
                "device_hwid": d.device_hwid[:12] + "..." if d.device_hwid else None,
                "registered_at": d.registered_at.isoformat() if d.registered_at else None,
                "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                "last_ip": d.last_ip,
                "is_active": d.is_active,
            }
            for d in devices
        ],
    )


@router.post("/licenses/{license_id}/revoke")
async def revoke_license(
    license_id: int,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a license. Customer can no longer use the bot."""
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    lic.is_revoked = True
    lic.is_active = False
    await _auto_backup(db)
    return {"status": "revoked", "license_key": lic.license_key}


@router.post("/licenses/{license_id}/activate")
async def activate_license(
    license_id: int,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Re-activate a revoked or inactive license."""
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    lic.is_revoked = False
    lic.is_active = True
    return {"status": "activated", "license_key": lic.license_key}


@router.post("/licenses/{license_id}/reset-hwid")
async def reset_hwid(
    license_id: int,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Reset HWID binding. Customer can use on a new PC."""
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    old_hwid = lic.hwid
    lic.hwid = None

    # Deactivate all existing devices
    await db.execute(
        update(Device)
        .where(Device.license_id == lic.id)
        .values(is_active=False)
    )

    return {
        "status": "hwid_reset",
        "license_key": lic.license_key,
        "old_hwid": old_hwid[:12] + "..." if old_hwid else None,
    }


@router.post("/licenses/{license_id}/extend")
async def extend_license(
    license_id: int,
    body: ExtendRequest,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Extend a license's expiry date."""
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    now = datetime.now(timezone.utc)
    # If key hasn't been activated yet, add to duration
    if not lic.activated_at and not lic.expires_at:
        if lic.plan in SUB_DAY_PLANS:
            # Sub-day plan: extend by converting days to minutes (or add minutes directly)
            current_min = lic.duration_minutes or 0
            lic.duration_minutes = current_min + (body.days * 24 * 60)  # days param treated as days
        else:
            current_days = lic.duration_days or 0
            lic.duration_days = current_days + body.days
        # Re-activate if was expired
        if not lic.is_revoked:
            lic.is_active = True
        await _auto_backup(db)
        duration_text = f"{lic.duration_minutes} dakika" if lic.plan in SUB_DAY_PLANS else f"{lic.duration_days} gün"
        return {
            "status": "extended",
            "license_key": lic.license_key,
            "new_expires_at": f"Not activated yet ({duration_text} on first use)",
        }

    # Extend from current expiry (or from now if already expired)
    base = lic.expires_at if lic.expires_at and lic.expires_at > now else now
    lic.expires_at = base + timedelta(days=body.days)

    # Re-activate if was expired
    if not lic.is_revoked:
        lic.is_active = True

    await _auto_backup(db)
    return {
        "status": "extended",
        "license_key": lic.license_key,
        "new_expires_at": lic.expires_at.isoformat(),
    }


@router.delete("/licenses/{license_id}")
async def delete_license(
    license_id: int,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete a license and all its devices."""
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    await db.execute(delete(Device).where(Device.license_id == lic.id))
    await db.delete(lic)
    await _auto_backup(db)
    return {"status": "deleted", "license_key": lic.license_key}


@router.post("/devices/{device_hwid}/ban")
async def ban_device(
    device_hwid: str,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Ban a device HWID across all licenses."""
    result = await db.execute(
        select(Device).where(Device.device_hwid == device_hwid)
    )
    devices = result.scalars().all()

    banned_count = 0
    for device in devices:
        device.is_active = False
        banned_count += 1

    # Record security event
    db.add(SecurityEvent(
        event_type="device_banned",
        device_hwid=device_hwid,
        detail=f"Admin banned device, affected {banned_count} records",
        severity="warning",
    ))

    return {"status": "banned", "device_hwid": device_hwid[:12] + "...", "affected": banned_count}


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Dashboard statistics."""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    total = (await db.execute(select(func.count(License.id)))).scalar() or 0
    active = (await db.execute(
        select(func.count(License.id)).where(
            License.is_active == True,
            License.is_revoked == False,
        )
    )).scalar() or 0

    expired = (await db.execute(
        select(func.count(License.id)).where(
            License.expires_at < now,
            License.is_revoked == False,
        )
    )).scalar() or 0

    revoked = (await db.execute(
        select(func.count(License.id)).where(License.is_revoked == True)
    )).scalar() or 0

    total_devices = (await db.execute(select(func.count(Device.id)))).scalar() or 0
    active_devices = (await db.execute(
        select(func.count(Device.id)).where(Device.is_active == True)
    )).scalar() or 0

    sec_events = (await db.execute(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.created_at >= day_ago)
    )).scalar() or 0

    token_ops = (await db.execute(
        select(func.count(TokenLog.id)).where(TokenLog.created_at >= day_ago)
    )).scalar() or 0

    # Unused = active, not revoked, never activated
    unused = (await db.execute(
        select(func.count(License.id)).where(
            License.is_active == True,
            License.is_revoked == False,
            License.activated_at == None,
        )
    )).scalar() or 0

    # Online = last_seen within last 2 minutes
    online_cutoff = now - timedelta(minutes=2)
    online_now = (await db.execute(
        select(func.count(License.id)).where(
            License.is_active == True,
            License.is_revoked == False,
            License.last_seen_at >= online_cutoff,
        )
    )).scalar() or 0

    return StatsResponse(
        total_licenses=total,
        active_licenses=active,
        expired_licenses=expired,
        revoked_licenses=revoked,
        unused_licenses=unused,
        online_now=online_now,
        total_devices=total_devices,
        active_devices=active_devices,
        security_events_24h=sec_events,
        token_ops_24h=token_ops,
    )


@router.get("/security-events")
async def list_security_events(
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
    hours: int = 24,
    severity: str = "",
    page: int = 1,
    per_page: int = 100,
):
    """List recent security events."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = select(SecurityEvent).where(
        SecurityEvent.created_at >= since
    ).order_by(SecurityEvent.created_at.desc())

    if severity:
        query = query.where(SecurityEvent.severity == severity)

    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "device_hwid": e.device_hwid[:12] + "..." if e.device_hwid else None,
                "ip_address": e.ip_address,
                "detail": e.detail,
                "severity": e.severity,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "total": len(events),
    }


# ---------- Online Users ----------

@router.get("/online")
async def get_online_users(
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
    minutes: int = 5,
):
    """Get currently online users (seen within last N minutes)."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    result = await db.execute(
        select(License).where(
            License.is_active == True,
            License.is_revoked == False,
            License.last_seen_at >= cutoff,
        ).order_by(License.last_seen_at.desc())
    )
    online = result.scalars().all()

    # Also get their devices
    users = []
    for lic in online:
        dev_result = await db.execute(
            select(Device).where(
                Device.license_id == lic.id,
                Device.is_active == True,
                Device.last_seen_at >= cutoff,
            )
        )
        devices = dev_result.scalars().all()

        users.append({
            "id": lic.id,
            "license_key": lic.license_key,
            "plan": lic.plan,
            "hwid": lic.hwid[:12] + "..." if lic.hwid else None,
            "last_seen_at": lic.last_seen_at.isoformat() if lic.last_seen_at else None,
            "last_ip": lic.last_ip,
            "notes": lic.notes,
            "devices": [
                {
                    "device_hwid": d.device_hwid[:12] + "..." if d.device_hwid else None,
                    "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                    "last_ip": d.last_ip,
                }
                for d in devices
            ],
        })

    return {
        "online_count": len(users),
        "cutoff_minutes": minutes,
        "users": users,
    }


# ---------- Bulk Import (Migration) ----------

# Eski plan adlarını yenilere eşle
OLD_PLAN_MAP = {"basic": "monthly", "premium": "monthly"}

class ImportKeyItem(BaseModel):
    key: str
    plan: str = "monthly"
    is_active: bool = True
    is_revoked: bool = False
    hwid: Optional[str] = None
    created_at: Optional[str] = None
    activated_at: Optional[str] = None
    expires_at: Optional[str] = None
    duration_days: Optional[int] = None
    duration_minutes: Optional[int] = None
    last_seen: Optional[str] = None
    last_ip: Optional[str] = None
    max_devices: int = 1
    note: str = ""
    notes: str = ""
    product: str = "gamestore"


class BulkImportRequest(BaseModel):
    keys: list[ImportKeyItem]


@router.post("/import")
async def bulk_import_licenses(
    body: BulkImportRequest,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Bulk import licenses from an external system.
    Preserves original keys, plans, HWID bindings, dates, and status.
    Skips duplicates (already existing keys).
    """
    imported = 0
    skipped = 0
    errors = []

    for item in body.keys:
        key = item.key.strip().upper()

        # Check duplicate
        exists = await db.execute(
            select(License).where(License.license_key == key)
        )
        if exists.scalar_one_or_none():
            skipped += 1
            continue

        # Parse dates
        def parse_dt(val):
            if not val:
                return None
            try:
                return datetime.fromisoformat(val)
            except Exception:
                return None

        try:
            note_text = item.notes or item.note or ""
            _activated_at = parse_dt(item.activated_at)
            _expires_at = parse_dt(item.expires_at)
            # Lazy expiration: kullanılmamış key'e expires_at atama
            if not _activated_at:
                _expires_at = None

            lic = License(
                license_key=key,
                plan=OLD_PLAN_MAP.get(item.plan, item.plan),
                product=(item.product or "gamestore").strip().lower() or "gamestore",
                is_active=item.is_active,
                is_revoked=item.is_revoked if item.is_revoked is not None else (not item.is_active),
                hwid=item.hwid,
                created_at=parse_dt(item.created_at) or datetime.now(timezone.utc),
                activated_at=_activated_at,
                expires_at=_expires_at,
                duration_days=item.duration_days,
                duration_minutes=item.duration_minutes,
                last_seen_at=parse_dt(item.last_seen),
                last_ip=item.last_ip,
                max_devices=item.max_devices if item.max_devices else 1,
                notes=f"[restored] {note_text}" if note_text else "[restored]",
            )
            db.add(lic)
            await db.flush()
            imported += 1
        except Exception as e:
            errors.append({"key": key, "error": str(e)})

    await db.commit()

    # Auto-backup after bulk import
    await _auto_backup(db)

    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
        "total_processed": len(body.keys),
    }
