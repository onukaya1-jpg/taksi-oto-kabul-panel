"""
License Auto-Backup — GitHub Persistence
==========================================
After every admin license operation, exports ALL licenses to GitHub repo
as data/licenses_backup.json. On startup, if DB is empty, restores from
this backup. This ensures keys NEVER get lost regardless of DB resets.

Required env vars (set in Render Dashboard):
  GITHUB_PAT           — Personal access token with repo write scope
  GITHUB_REPO          — e.g. "onurtenktr-commits/gamestore-auth-server"
  GITHUB_BACKUP_PATH   — file path in repo (default: data/licenses_backup.json)
"""

import json
import base64
import asyncio
import structlog
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.settings import get_settings

logger = structlog.get_logger(__name__)

GITHUB_API = "https://api.github.com"
BACKUP_FILE_PATH = "data/licenses_backup.json"


def _get_github_headers() -> Optional[dict]:
    """Get GitHub API headers. Returns None if not configured."""
    settings = get_settings()
    pat = getattr(settings, "GITHUB_PAT", "") or ""
    if not pat:
        return None
    return {
        "Authorization": f"token {pat}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _get_repo() -> str:
    settings = get_settings()
    return getattr(settings, "GITHUB_REPO", "") or "onurtenktr-commits/gamestore-auth-server"


async def backup_licenses_to_github(db_session) -> dict:
    """
    Export all licenses from DB and push to GitHub as JSON.
    Called automatically after every admin license CRUD operation.
    Returns {"status": "ok", "backed_up": N} or {"status": "skipped/error", ...}.
    """
    from app.models import License
    from sqlalchemy import select

    headers = _get_github_headers()
    if not headers:
        logger.warning("github_backup_skipped", reason="GITHUB_PAT not configured")
        return {"status": "skipped", "reason": "GITHUB_PAT not set"}

    repo = _get_repo()
    file_path = BACKUP_FILE_PATH

    try:
        # 1. Export all licenses from DB
        result = await db_session.execute(select(License).order_by(License.id))
        licenses = result.scalars().all()

        backup_data = {
            "_comment": "Auto-backup — DO NOT EDIT. Updated automatically after every admin operation.",
            "backed_up_at": datetime.now(timezone.utc).isoformat(),
            "total": len(licenses),
            "licenses": [],
        }

        for lic in licenses:
            backup_data["licenses"].append({
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

        content_json = json.dumps(backup_data, indent=2, ensure_ascii=False)
        content_b64 = base64.b64encode(content_json.encode("utf-8")).decode("ascii")

        # 2. Get current file SHA (needed for update)
        url = f"{GITHUB_API}/repos/{repo}/contents/{file_path}"
        async with httpx.AsyncClient(timeout=30) as client:
            get_resp = await client.get(url, headers=headers, params={"ref": "main"})
            sha = None
            if get_resp.status_code == 200:
                sha = get_resp.json().get("sha")

            # 3. Push to GitHub (create or update)
            payload = {
                "message": f"Auto-backup: {len(licenses)} licenses ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC)",
                "content": content_b64,
                "branch": "main",
            }
            if sha:
                payload["sha"] = sha

            put_resp = await client.put(url, headers=headers, json=payload)

            if put_resp.status_code in (200, 201):
                logger.info("github_backup_success", licenses=len(licenses))
                return {"status": "ok", "backed_up": len(licenses)}
            else:
                err = put_resp.text[:200]
                logger.error("github_backup_failed", status=put_resp.status_code, error=err)
                return {"status": "error", "code": put_resp.status_code, "detail": err}

    except Exception as e:
        logger.error("github_backup_exception", error=str(e))
        return {"status": "error", "detail": str(e)}


async def restore_licenses_from_github() -> dict:
    """
    Fetch licenses_backup.json from GitHub and restore any missing keys to DB.
    Called on startup if DB has fewer licenses than backup.
    Returns {"status": ..., "restored": N, "skipped": N}.
    """
    from app.models import License
    from app.database import get_session_factory
    from sqlalchemy import select, func

    headers = _get_github_headers()
    if not headers:
        logger.info("github_restore_skipped", reason="GITHUB_PAT not configured")
        return {"status": "skipped", "reason": "GITHUB_PAT not set"}

    repo = _get_repo()
    file_path = BACKUP_FILE_PATH

    try:
        # 1. Fetch backup from GitHub
        url = f"{GITHUB_API}/repos/{repo}/contents/{file_path}"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=headers, params={"ref": "main"})

        if resp.status_code == 404:
            logger.info("github_restore_no_backup", reason="No backup file in repo")
            return {"status": "skipped", "reason": "No backup file found"}

        if resp.status_code != 200:
            logger.error("github_restore_fetch_failed", status=resp.status_code)
            return {"status": "error", "code": resp.status_code}

        data = resp.json()
        content_b64 = data.get("content", "")
        content_json = base64.b64decode(content_b64).decode("utf-8")
        backup = json.loads(content_json)

        # Support both formats: list (old) and dict with "licenses" key (new)
        if isinstance(backup, list):
            backup_licenses = backup
        else:
            backup_licenses = backup.get("licenses", [])

        if not backup_licenses:
            return {"status": "skipped", "reason": "Backup is empty"}

        # 2. Restore missing keys
        factory = get_session_factory()
        restored = 0
        skipped = 0

        for item in backup_licenses:
            key = (item.get("key") or item.get("license_key") or "").strip().upper()
            if not key:
                skipped += 1
                continue
            async with factory() as db:
                exists = await db.execute(select(License).where(License.license_key == key))
                if exists.scalar_one_or_none():
                    skipped += 1
                    continue

                # Parse dates
                def parse_dt(val):
                    if not val:
                        return None
                    try:
                        dt = datetime.fromisoformat(val)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt
                    except Exception:
                        return None

                _activated_at = parse_dt(item.get("activated_at"))
                _expires_at = parse_dt(item.get("expires_at"))
                # Lazy expiration: kullanılmamış key'e expires_at atama
                if not _activated_at:
                    _expires_at = None

                # Map old plan names to new ones
                _plan = item.get("plan", "monthly")
                if _plan in ("basic", "premium"):
                    _plan = "monthly"

                lic = License(
                    license_key=key,
                    plan=_plan,
                    product=(item.get("product") or "gamestore").strip().lower() or "gamestore",
                    is_active=item.get("is_active", True),
                    is_revoked=item.get("is_revoked", False),
                    hwid=item.get("hwid"),
                    created_at=parse_dt(item.get("created_at")) or datetime.now(timezone.utc),
                    activated_at=_activated_at,
                    expires_at=_expires_at,
                    duration_days=item.get("duration_days"),
                    duration_minutes=item.get("duration_minutes"),
                    last_seen_at=parse_dt(item.get("last_seen") or item.get("last_seen_at")),
                    last_ip=item.get("last_ip"),
                    max_devices=item.get("max_devices", 1),
                    notes=item.get("notes", "") or "[github-restore]",
                )
                db.add(lic)
                await db.commit()
                restored += 1
                logger.info("github_restore_key", key=key, plan=lic.plan)

        logger.info("github_restore_complete", restored=restored, skipped=skipped)
        return {"status": "ok", "restored": restored, "skipped": skipped}

    except Exception as e:
        logger.error("github_restore_exception", error=str(e))
        return {"status": "error", "detail": str(e)}
