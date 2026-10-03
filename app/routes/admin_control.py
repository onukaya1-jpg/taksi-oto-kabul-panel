"""
Admin Control Routes — Online Monitoring & Remote Bot Control
==============================================================
Protected by ADMIN_API_KEY header (same as admin.py).

GET    /admin/control/online          — List all currently online users with bot status
GET    /admin/control/sessions         — Session history (last 50)
GET    /admin/control/user/{hwid}      — Detailed info for a specific device
POST   /admin/control/command/{hwid}   — Send command to a specific device
POST   /admin/control/broadcast        — Send command to ALL online devices
POST   /admin/control/stop-all         — Emergency: stop all bots
POST   /admin/control/message/{hwid}   — Send message to a specific device
DELETE /admin/control/bot-status/{hwid} — Clear bot status for device
GET    /admin/control/panel            — Admin control panel v2 UI
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete as sa_delete, func

from app.database import get_db
from app.models import (
    License, Device, OnlineSession, BotStatus, AdminCommandQueue,
)
from app.routes.admin import verify_admin_key
from app.settings import get_settings
import hashlib
import hmac

router = APIRouter(prefix="/admin/control", tags=["admin-control"])

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


# ---------- Request Schemas ----------

class SendCommandRequest(BaseModel):
    action: str = Field(..., pattern="^(stop_bot|start_bot|restart_bot|disconnect|show_message|kill_session)$")
    param: str = Field(default="", max_length=500)


class BroadcastRequest(BaseModel):
    action: str = Field(..., pattern="^(stop_bot|start_bot|restart_bot|disconnect|show_message|kill_session)$")
    param: str = Field(default="", max_length=500)


class SendMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=500)


# ---------- Helpers ----------

def _make_aware(dt: datetime) -> datetime:
    if dt and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _sign_command(hwid: str, action: str, param: str) -> str:
    """HMAC-SHA256 signature for command integrity verification."""
    secret = get_settings().COMMAND_HMAC_SECRET
    if not secret:
        return ""
    msg = f"{hwid}:{action}:{param}"
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def _is_online(last_seen: datetime | None, threshold_seconds: int = 30) -> bool:
    """Consider a device online if last_seen is within threshold."""
    if not last_seen:
        return False
    last_seen = _make_aware(last_seen)
    return (datetime.now(timezone.utc) - last_seen).total_seconds() < threshold_seconds


# ---------- Route Handlers ----------

@router.get("/panel", include_in_schema=False)
async def control_panel():
    """Serve the admin control panel v2 UI."""
    html_path = _STATIC_DIR / "admin_control.html"
    if not html_path.exists():
        raise HTTPException(404, "Control panel not found")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@router.get("/online")
async def get_online_users(
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """List all currently online users with their bot status."""
    # Online = last_seen_at within 30 seconds
    threshold = datetime.now(timezone.utc) - timedelta(seconds=30)

    result = await db.execute(
        select(Device, License).join(License, Device.license_id == License.id).where(
            Device.last_seen_at != None,
            Device.last_seen_at > threshold,
            Device.is_active == True,
        )
    )
    rows = result.all()

    users = []
    for device, lic in rows:
        # Get bot status if available
        bs_result = await db.execute(
            select(BotStatus).where(BotStatus.device_hwid == device.device_hwid)
        )
        bs = bs_result.scalar_one_or_none()

        user_info = {
            "device_hwid": device.device_hwid,
            "license_key": lic.license_key,
            "license_id": lic.id,
            "plan": lic.plan,
            "ip_address": device.last_ip or "",
            "last_seen": _make_aware(device.last_seen_at).isoformat() if device.last_seen_at else None,
            "online_seconds": int((datetime.now(timezone.utc) - _make_aware(device.last_seen_at)).total_seconds()) if device.last_seen_at else 0,
        }

        if bs:
            user_info["bot_status"] = {
                "running": bs.bot_running,
                "game_connected": bs.game_connected,
                "character_name": bs.character_name or "",
                "state": bs.bot_state or "idle",
                "mobs_killed": bs.mobs_killed,
                "items_collected": bs.items_collected,
                "death_count": bs.death_count,
                "potions_used": bs.potions_used,
                "uptime_seconds": bs.uptime_seconds,
                "hp": bs.hp,
                "max_hp": bs.max_hp,
                "mp": bs.mp,
                "max_mp": bs.max_mp,
                "pos_x": bs.pos_x,
                "pos_y": bs.pos_y,
                "last_updated": _make_aware(bs.last_updated).isoformat() if bs.last_updated else None,
            }
        else:
            user_info["bot_status"] = None

        users.append(user_info)

    return {"online_count": len(users), "users": users}


@router.get("/sessions")
async def get_sessions(
    limit: int = 50,
    hwid: str | None = None,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Get session history. Optionally filter by device HWID."""
    query = select(OnlineSession).order_by(OnlineSession.started_at.desc())
    if hwid:
        query = query.where(OnlineSession.device_hwid == hwid)
    query = query.limit(min(limit, 200))

    result = await db.execute(query)
    sessions = result.scalars().all()

    return {
        "count": len(sessions),
        "sessions": [
            {
                "id": s.id,
                "license_id": s.license_id,
                "device_hwid": s.device_hwid,
                "character_name": s.character_name,
                "started_at": _make_aware(s.started_at).isoformat() if s.started_at else None,
                "ended_at": _make_aware(s.ended_at).isoformat() if s.ended_at else None,
                "duration_seconds": s.duration_seconds,
                "ip_address": s.ip_address,
                "is_active": s.ended_at is None,
            }
            for s in sessions
        ],
    }


@router.get("/user/{hwid}")
async def get_user_detail(
    hwid: str,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed info for a specific device including bot status and session history."""
    # Device info
    result = await db.execute(
        select(Device).where(Device.device_hwid == hwid)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Device not found")

    # License info
    result = await db.execute(select(License).where(License.id == device.license_id))
    lic = result.scalar_one_or_none()

    # Bot status
    result = await db.execute(select(BotStatus).where(BotStatus.device_hwid == hwid))
    bs = result.scalar_one_or_none()

    # Recent sessions
    result = await db.execute(
        select(OnlineSession).where(
            OnlineSession.device_hwid == hwid
        ).order_by(OnlineSession.started_at.desc()).limit(20)
    )
    sessions = result.scalars().all()

    # Total online time
    result = await db.execute(
        select(func.sum(OnlineSession.duration_seconds)).where(
            OnlineSession.device_hwid == hwid,
            OnlineSession.duration_seconds != None,
        )
    )
    total_seconds = result.scalar() or 0

    is_online = _is_online(device.last_seen_at) if device.last_seen_at else False

    return {
        "device": {
            "hwid": device.device_hwid,
            "license_id": device.license_id,
            "registered_at": _make_aware(device.registered_at).isoformat() if device.registered_at else None,
            "last_seen": _make_aware(device.last_seen_at).isoformat() if device.last_seen_at else None,
            "last_ip": device.last_ip,
            "is_online": is_online,
        },
        "license": {
            "key": lic.license_key if lic else None,
            "plan": lic.plan if lic else None,
            "is_active": lic.is_active if lic else False,
            "expires_at": _make_aware(lic.expires_at).isoformat() if lic and lic.expires_at else None,
        } if lic else None,
        "bot_status": {
            "running": bs.bot_running,
            "game_connected": bs.game_connected,
            "character_name": bs.character_name or "",
            "state": bs.bot_state or "idle",
            "mobs_killed": bs.mobs_killed,
            "items_collected": bs.items_collected,
            "death_count": bs.death_count,
            "potions_used": bs.potions_used,
            "uptime_seconds": bs.uptime_seconds,
            "hp": bs.hp,
            "max_hp": bs.max_hp,
            "mp": bs.mp,
            "max_mp": bs.max_mp,
            "pos_x": bs.pos_x,
            "pos_y": bs.pos_y,
        } if bs else None,
        "total_online_seconds": total_seconds,
        "sessions": [
            {
                "started_at": _make_aware(s.started_at).isoformat() if s.started_at else None,
                "ended_at": _make_aware(s.ended_at).isoformat() if s.ended_at else None,
                "duration_seconds": s.duration_seconds,
                "character_name": s.character_name,
                "is_active": s.ended_at is None,
            }
            for s in sessions
        ],
    }


@router.post("/command/{hwid}")
async def send_command(
    hwid: str,
    body: SendCommandRequest,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Send a command to a specific device (delivered via next heartbeat)."""
    cmd = AdminCommandQueue(
        device_hwid=hwid,
        action=body.action,
        param=body.param if body.param else None,
        signature=_sign_command(hwid, body.action, body.param or ""),
    )
    db.add(cmd)
    await db.commit()
    return {"status": "queued", "command_id": cmd.id, "action": body.action, "target": hwid}


@router.post("/message/{hwid}")
async def send_message(
    hwid: str,
    body: SendMessageRequest,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Send a popup message to a specific device."""
    cmd = AdminCommandQueue(
        device_hwid=hwid,
        action="show_message",
        param=body.message,
        signature=_sign_command(hwid, "show_message", body.message),
    )
    db.add(cmd)
    await db.commit()
    return {"status": "queued", "command_id": cmd.id, "message": body.message, "target": hwid}


@router.post("/broadcast")
async def broadcast_command(
    body: BroadcastRequest,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Send a command to ALL currently online devices."""
    threshold = datetime.now(timezone.utc) - timedelta(seconds=90)
    result = await db.execute(
        select(Device.device_hwid).where(
            Device.last_seen_at != None,
            Device.last_seen_at > threshold,
            Device.is_active == True,
        )
    )
    online_hwids = [row[0] for row in result.all()]

    for hwid in online_hwids:
        db.add(AdminCommandQueue(
            device_hwid=hwid,
            action=body.action,
            param=body.param if body.param else None,
            signature=_sign_command(hwid, body.action, body.param or ""),
        ))
    await db.commit()

    return {"status": "broadcast_queued", "target_count": len(online_hwids), "action": body.action}


@router.post("/stop-all")
async def stop_all_bots(
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Emergency: send stop_bot to ALL online devices."""
    threshold = datetime.now(timezone.utc) - timedelta(seconds=90)
    result = await db.execute(
        select(Device.device_hwid).where(
            Device.last_seen_at != None,
            Device.last_seen_at > threshold,
            Device.is_active == True,
        )
    )
    online_hwids = [row[0] for row in result.all()]

    for hwid in online_hwids:
        db.add(AdminCommandQueue(
            device_hwid=hwid,
            action="stop_bot",
            signature=_sign_command(hwid, "stop_bot", ""),
        ))
    await db.commit()

    return {"status": "stop_all_queued", "target_count": len(online_hwids)}


@router.delete("/bot-status/{hwid}")
async def clear_bot_status(
    hwid: str,
    _: bool = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_db),
):
    """Clear bot status record for a device."""
    await db.execute(sa_delete(BotStatus).where(BotStatus.device_hwid == hwid))
    await db.commit()
    return {"status": "cleared", "device_hwid": hwid}
