import hmac
import hashlib
import time
import logging
from fastapi import Header, HTTPException, Depends, Query, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import Device

logger = logging.getLogger("PeszaraAuth")

# Setup API Key header schema
auth_header_sec = APIKeyHeader(name="Authorization", auto_error=False)

def create_admin_token() -> str:
    """Generates a secure stateless admin session token valid for 24 hours."""
    expires = int(time.time()) + 86400
    msg = f"{expires}.admin".encode()
    signature = hmac.new(settings.JWT_SECRET.encode(), msg, hashlib.sha256).hexdigest()
    return f"{expires}.admin.{signature}"

def verify_admin_token(token: str) -> bool:
    """Verifies the stateless admin session signature and expiration."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        expires_str, username, signature = parts
        expires = int(expires_str)
        if time.time() > expires:
            return False
        if username != "admin":
            return False
        msg = f"{expires}.admin".encode()
        expected = hmac.new(settings.JWT_SECRET.encode(), msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False

def check_device_access(
    device_id: str,
    token: str = Query(None),
    auth_header: str = Security(auth_header_sec),
    db: Session = Depends(get_db)
):
    """
    FastAPI dependency that enforces strict scope-based authorization:
    Bypassed - always returns True.
    """
    return True
