"""
Feature Routes — Token-Protected Feature Access
=================================================
POST /feature/use       — Verify token + nonce for feature access
POST /feature/offsets   — Return game offsets (requires offset:read scope)
"""

import time

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_license_service
from app.licensing import LicenseService, LicenseServiceError

router = APIRouter(prefix="/feature", tags=["feature"])


# ---------- Schemas ----------

class FeatureUseRequest(BaseModel):
    token: str = Field(..., min_length=32)
    feature: str = Field(..., min_length=1, max_length=64)
    device_hwid: str = Field(..., min_length=16, max_length=128)
    nonce: str = Field(..., min_length=16, max_length=64)

class FeatureUseResponse(BaseModel):
    allowed: bool
    license_id: str
    scope: list[str]
    remaining_ttl: int

class OffsetRequest(BaseModel):
    token: str = Field(..., min_length=32)
    device_hwid: str = Field(..., min_length=16, max_length=128)
    nonce: str = Field(..., min_length=16, max_length=64)
    game_version: str = Field(default="", max_length=32)

class OffsetResponse(BaseModel):
    allowed: bool
    offsets: dict = {}
    version: str = ""


# ---------- Handlers ----------

@router.post("/use", response_model=FeatureUseResponse)
async def feature_use(
    body: FeatureUseRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: LicenseService = Depends(get_license_service),
):
    """
    Verify a signed token with nonce for feature access.
    Each request must include a unique nonce — replays are rejected.
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        result = await svc.verify_feature_use(
            db=db,
            token=body.token,
            feature=body.feature,
            device_hwid=body.device_hwid,
            nonce=body.nonce,
            ip_address=client_ip,
        )
        return FeatureUseResponse(**result)
    except LicenseServiceError as e:
        return JSONResponse(
            status_code=e.status,
            content={"error": e.code, "message": e.message},
        )


@router.post("/offsets", response_model=OffsetResponse)
async def get_offsets(
    body: OffsetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: LicenseService = Depends(get_license_service),
):
    """
    Return game offsets for authenticated clients with 'offset:read' scope.
    Offsets are loaded from the server-side game_offsets.json.
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        result = await svc.verify_feature_use(
            db=db,
            token=body.token,
            feature="offset_read",
            device_hwid=body.device_hwid,
            nonce=body.nonce,
            ip_address=client_ip,
        )
    except LicenseServiceError as e:
        return JSONResponse(
            status_code=e.status,
            content={"error": e.code, "message": e.message},
        )

    # Load offsets from file (server-side, NOT shipped with client)
    import json
    from pathlib import Path

    offset_path = Path(__file__).parent.parent.parent / "data" / "game_offsets.json"
    offsets = {}
    version = ""
    if offset_path.exists():
        try:
            data = json.loads(offset_path.read_text(encoding="utf-8"))
            offsets = data.get("offsets", data)
            version = data.get("version", "")
        except Exception:
            pass

    return OffsetResponse(allowed=True, offsets=offsets, version=version)
