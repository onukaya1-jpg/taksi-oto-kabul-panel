"""
Ed25519 Token Engine
=====================
Server-side Ed25519 token signing and verification.
Supports key rotation with overlap period.

Token format:
  SIGNATURE_HEX.PAYLOAD_BASE64

Payload JSON:
  {
    "iss": "gamestore-auth",
    "sub": "<license_id>",
    "hwid": "<device_hwid>",
    "exp": <unix_timestamp>,
    "iat": <unix_timestamp>,
    "nonce": "<random_hex>",
    "scope": ["feature:use", "offset:read"],
    "kid": "<key_id>"
  }

SECURITY:
  - Private keys are NEVER written to disk by this module.
  - Key material is loaded from vault/HSM or environment.
  - Ephemeral keys are generated ONLY in development mode.
"""

import base64
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class TokenPayload:
    """Structured token payload."""
    iss: str = "gamestore-auth"
    sub: str = ""          # license_id
    hwid: str = ""         # device hardware id
    exp: int = 0           # expiry unix timestamp
    iat: int = 0           # issued at
    nonce: str = ""        # replay protection
    scope: list[str] = field(default_factory=list)
    kid: str = ""          # key id (for rotation)

    def to_dict(self) -> dict:
        return {
            "iss": self.iss,
            "sub": self.sub,
            "hwid": self.hwid,
            "exp": self.exp,
            "iat": self.iat,
            "nonce": self.nonce,
            "scope": self.scope,
            "kid": self.kid,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TokenPayload":
        return cls(
            iss=d.get("iss", ""),
            sub=d.get("sub", ""),
            hwid=d.get("hwid", ""),
            exp=d.get("exp", 0),
            iat=d.get("iat", 0),
            nonce=d.get("nonce", ""),
            scope=d.get("scope", []),
            kid=d.get("kid", ""),
        )

    @property
    def is_expired(self) -> bool:
        return self.exp < int(time.time())


@dataclass
class KeyPair:
    """Ed25519 key pair with metadata."""
    key_id: str
    signing_key: SigningKey
    verify_key: VerifyKey
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0  # 0 = no expiry (current active key)

    @property
    def public_key_hex(self) -> str:
        return self.verify_key.encode().hex()

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at


class TokenEngine:
    """
    Ed25519 token signing and verification engine.
    Supports key rotation with overlap verification period.
    """

    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._active_key: Optional[KeyPair] = None
        self._verify_keys: dict[str, KeyPair] = {}  # kid -> KeyPair (for rotation)

    # ----------------------------------------------------------
    # Key Management
    # ----------------------------------------------------------

    def load_key_from_bytes(self, private_key_bytes: bytes, key_id: str = "primary") -> None:
        """Load Ed25519 private key from raw bytes (32 bytes)."""
        sk = SigningKey(private_key_bytes)
        vk = sk.verify_key
        kp = KeyPair(key_id=key_id, signing_key=sk, verify_key=vk)
        self._active_key = kp
        self._verify_keys[key_id] = kp
        logger.info("ed25519_key_loaded", key_id=key_id, public_key=vk.encode().hex()[:16] + "...")

    def load_key_from_hex(self, private_key_hex: str, key_id: str = "primary") -> None:
        """Load Ed25519 private key from hex string."""
        self.load_key_from_bytes(bytes.fromhex(private_key_hex), key_id)

    def load_key_from_file(self, path: str, key_id: str = "primary") -> None:
        """Load Ed25519 private key from PEM-like file (raw 32 bytes or hex)."""
        with open(path, "rb") as f:
            data = f.read().strip()
        if len(data) == 32:
            self.load_key_from_bytes(data, key_id)
        elif len(data) == 64:
            self.load_key_from_hex(data.decode("ascii"), key_id)
        else:
            raise ValueError(f"Invalid key file: expected 32 bytes (raw) or 64 chars (hex), got {len(data)}")

    def generate_ephemeral_key(self, key_id: str = "ephemeral") -> str:
        """
        Generate ephemeral key pair for development.
        WARNING: This key is NOT persisted. Tokens become invalid on restart.
        """
        sk = SigningKey.generate()
        vk = sk.verify_key
        kp = KeyPair(key_id=key_id, signing_key=sk, verify_key=vk)
        self._active_key = kp
        self._verify_keys[key_id] = kp
        logger.warning(
            "ephemeral_key_generated",
            key_id=key_id,
            warning="DO NOT USE IN PRODUCTION — tokens invalidated on restart",
        )
        return vk.encode().hex()

    def add_verify_key(self, public_key_hex: str, key_id: str, expires_at: float = 0.0) -> None:
        """
        Add a public key for verification only (used during key rotation).
        Old keys remain valid for verification during the overlap period.
        """
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        kp = KeyPair(
            key_id=key_id,
            signing_key=SigningKey.generate(),  # placeholder, not used
            verify_key=vk,
            expires_at=expires_at,
        )
        self._verify_keys[key_id] = kp
        logger.info("verify_key_added", key_id=key_id, expires_at=expires_at)

    def rotate_key(self, new_private_key_bytes: bytes, new_key_id: str,
                   overlap_hours: int = 24) -> None:
        """
        Rotate to a new signing key. Old key remains valid for verification
        during the overlap period.
        """
        if self._active_key:
            old = self._active_key
            old.expires_at = time.time() + (overlap_hours * 3600)
            self._verify_keys[old.key_id] = old
            logger.info("key_rotated_old_key_retained",
                        old_key_id=old.key_id,
                        expires_in_hours=overlap_hours)

        self.load_key_from_bytes(new_private_key_bytes, new_key_id)

    def cleanup_expired_keys(self) -> int:
        """Remove expired verification keys. Returns count of removed keys."""
        expired = [kid for kid, kp in self._verify_keys.items() if kp.is_expired]
        for kid in expired:
            del self._verify_keys[kid]
        if expired:
            logger.info("expired_keys_cleaned", count=len(expired), key_ids=expired)
        return len(expired)

    # ----------------------------------------------------------
    # Token Operations
    # ----------------------------------------------------------

    def create_token(
        self,
        license_id: str,
        device_hwid: str,
        scope: list[str] | None = None,
        ttl: int | None = None,
    ) -> tuple[str, TokenPayload]:
        """
        Create a signed Ed25519 token.

        Returns:
            (token_string, payload) — token format: SIGNATURE_HEX.PAYLOAD_BASE64
        """
        if not self._active_key:
            raise RuntimeError("No signing key loaded")

        now = int(time.time())
        nonce = os.urandom(16).hex()

        payload = TokenPayload(
            iss="gamestore-auth",
            sub=license_id,
            hwid=device_hwid,
            exp=now + (ttl or self._ttl),
            iat=now,
            nonce=nonce,
            scope=scope or ["feature:use", "offset:read"],
            kid=self._active_key.key_id,
        )

        payload_json = json.dumps(payload.to_dict(), separators=(",", ":"), sort_keys=True)
        payload_bytes = payload_json.encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")

        # Sign the base64-encoded payload
        signed = self._active_key.signing_key.sign(payload_b64.encode("ascii"))
        signature_hex = signed.signature.hex()

        token = f"{signature_hex}.{payload_b64}"
        return token, payload

    def verify_token(self, token: str) -> TokenPayload:
        """
        Verify and decode a signed token.

        Raises:
            ValueError: Invalid token format or signature
            PermissionError: Token expired

        Returns:
            Decoded TokenPayload
        """
        # Parse token
        parts = token.split(".", 1)
        if len(parts) != 2:
            raise ValueError("Invalid token format")

        signature_hex, payload_b64 = parts

        try:
            signature = bytes.fromhex(signature_hex)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid signature encoding") from exc

        # Decode payload to find kid
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload_dict = json.loads(payload_bytes)
        except Exception as exc:
            raise ValueError("Invalid payload encoding") from exc

        kid = payload_dict.get("kid", "")

        # Find verification key
        key_pair = self._verify_keys.get(kid)
        if not key_pair:
            # Try all non-expired keys
            for kp in self._verify_keys.values():
                if not kp.is_expired:
                    try:
                        kp.verify_key.verify(payload_b64.encode("ascii"), signature)
                        key_pair = kp
                        break
                    except BadSignatureError:
                        continue
            if not key_pair:
                raise ValueError(f"Unknown or expired key ID: {kid}")

        # Verify signature
        try:
            key_pair.verify_key.verify(payload_b64.encode("ascii"), signature)
        except BadSignatureError as exc:
            raise ValueError("Invalid token signature") from exc

        payload = TokenPayload.from_dict(payload_dict)

        # Check expiry
        if payload.is_expired:
            raise PermissionError("Token expired")

        # Check issuer
        if payload.iss != "gamestore-auth":
            raise ValueError("Invalid token issuer")

        return payload

    # ----------------------------------------------------------
    # Info
    # ----------------------------------------------------------

    @property
    def active_key_id(self) -> str | None:
        return self._active_key.key_id if self._active_key else None

    @property
    def active_public_key_hex(self) -> str | None:
        return self._active_key.public_key_hex if self._active_key else None

    @property
    def verify_key_count(self) -> int:
        return len(self._verify_keys)

    def get_public_keys(self) -> dict[str, str]:
        """Return all non-expired public keys: {kid: public_key_hex}."""
        return {
            kid: kp.public_key_hex
            for kid, kp in self._verify_keys.items()
            if not kp.is_expired
        }
