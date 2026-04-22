"""
Auth router — session-based authentication with role-based access control.

  POST /api/auth/login        -> username + password → session token + HttpOnly cookie
  POST /api/auth/logout       -> invalidate current session
  GET  /api/auth/me           -> current user info (requires auth)
  GET  /api/auth/users        -> list all users (admin only)
  POST /api/auth/users        -> create user (admin only)
  PUT  /api/auth/users/{id}   -> update user role/password/active (admin only)
  DELETE /api/auth/users/{id} -> delete user (admin only)

Roles:
  admin    — full access: manage users, all campaign operations, settings
  operator — create/run campaigns, view analytics, no user management
  viewer   — read-only: view campaigns and analytics, no mutations

Security:
  - Passwords hashed with bcrypt (SHA-256 legacy hashes auto-upgraded on login)
  - Session tokens via HttpOnly cookie (JS-inaccessible) + Authorization header fallback
  - Login rate-limiting: 10 attempts per IP per 15 minutes -> 429 Too Many Requests
  - Expired sessions cleaned up by background task in main.py
"""
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import bcrypt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Header, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
import audit as audit_module
import models

router = APIRouter(prefix="/api/auth", tags=["auth"])

SESSION_TTL_HOURS = 8
COOKIE_NAME       = "phishsim_session"

# ── Rate limiter (in-memory, per IP) ─────────────────────────────────────────
_rate_store: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, 0.0))
RATE_LIMIT_MAX    = 10
RATE_LIMIT_WINDOW = 15 * 60  # seconds

def _check_rate_limit(ip: str):
    count, window_start = _rate_store[ip]
    now = time.time()
    if now - window_start > RATE_LIMIT_WINDOW:
        _rate_store[ip] = (1, now)
        return
    count += 1
    _rate_store[ip] = (count, window_start)
    if count > RATE_LIMIT_MAX:
        retry_after = int(RATE_LIMIT_WINDOW - (now - window_start))
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {retry_after // 60} minutes.",
            headers={"Retry-After": str(retry_after)},
        )

def _clear_rate_limit(ip: str):
    _rate_store.pop(ip, None)


# ── Password hashing (bcrypt with SHA-256 legacy migration) ──────────────────

def _hash_password(password: str) -> str:
    """Hash with bcrypt (12 rounds). Returns bcrypt hash string."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify password. Supports:
    - New bcrypt hashes: starts with $2b$ or $2a$
    - Legacy SHA-256 hashes: salt:hex  (auto-upgraded on next login)
    """
    if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False
    else:
        import hashlib
        try:
            salt, h = stored_hash.split(":", 1)
            computed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
            return secrets.compare_digest(computed, h)
        except Exception:
            return False


def _store_hash(password: str) -> str:
    return _hash_password(password)


# ── Session token extraction ──────────────────────────────────────────────────

def _extract_token(authorization: str = "", cookie_token: str = "") -> Optional[str]:
    """
    Extract token from:
    1. HttpOnly cookie  (preferred — JS-inaccessible, CVE-8 fix)
    2. Authorization: Bearer header  (fallback for API clients)
    """
    if cookie_token:
        return cookie_token.strip()
    if authorization.startswith("Bearer "):
        return authorization[7:].strip()
    return None


# ── Auth dependencies (used by all other routers) ────────────────────────────

def require_auth(
    authorization: str = Header(default=""),
    phishsim_session: str = Cookie(default=""),
    db: Session = Depends(get_db),
) -> models.User:
    """Dependency: returns the current User or raises 401."""
    token = _extract_token(authorization, phishsim_session)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")
    session = (
        db.query(models.UserSession)
        .filter(models.UserSession.token == token)
        .first()
    )
    if not session:
        raise HTTPException(status_code=401, detail="Session not found. Please log in again.")
    if session.expires_at < datetime.utcnow():
        # SEC-02 fix: eagerly delete the expired session so it is not returned
        # by subsequent queries before the hourly cleanup job runs.
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    if not session.user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled.")
    return session.user


def require_admin(user: models.User = Depends(require_auth)) -> models.User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    return user


def require_operator(user: models.User = Depends(require_auth)) -> models.User:
    if user.role not in ("admin", "operator"):
        raise HTTPException(status_code=403, detail="Operator or admin privileges required.")
    return user


# ── Schemas ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class CreateUserRequest(BaseModel):
    username: str
    password: str
    email: str = ""
    role: str = "viewer"

class UpdateUserRequest(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/login")
def login(data: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    user = db.query(models.User).filter(models.User.username == data.username).first()
    if not user or not _verify_password(data.password, user.password_hash):
        # Audit failed login attempt
        try:
            audit_module.write(db, "auth.login_failed", actor=data.username,
                               details={"reason": "invalid_credentials"}, ip_address=client_ip)
            db.commit()
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled. Contact your administrator.")

    # Auto-upgrade legacy SHA-256 hash to bcrypt on successful login
    if not (user.password_hash.startswith("$2b$") or user.password_hash.startswith("$2a$")):
        user.password_hash = _hash_password(data.password)

    token = models.UserSession.generate()
    now   = datetime.utcnow()
    session = models.UserSession(
        user_id=user.id,
        token=token,
        created_at=now,
        expires_at=now + timedelta(hours=SESSION_TTL_HOURS),
    )
    db.add(session)
    user.last_login_at = now
    db.commit()

    _clear_rate_limit(client_ip)

    # Audit successful login
    try:
        audit_module.write(db, "auth.login", actor=user.username,
                           details={"role": user.role}, ip_address=client_ip)
        db.commit()
    except Exception:
        pass

    # HttpOnly cookie — invisible to JavaScript (CVE-8 fix)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_HOURS * 3600,
        secure=False,  # Change to True once running on HTTPS
    )

    return {
        "token": token,
        "expires_in": SESSION_TTL_HOURS * 3600,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


@router.post("/logout")
def logout(
    response: Response,
    authorization: str = Header(default=""),
    phishsim_session: str = Cookie(default=""),
    db: Session = Depends(get_db),
):
    token = _extract_token(authorization, phishsim_session)
    if token:
        session = db.query(models.UserSession).filter(models.UserSession.token == token).first()
        actor = session.user.username if session and session.user else "unknown"
        db.query(models.UserSession).filter(models.UserSession.token == token).delete()
        try:
            audit_module.write(db, "auth.logout", actor=actor)
        except Exception:
            pass
        db.commit()
    response.delete_cookie(key=COOKIE_NAME)
    return {"status": "logged_out"}


@router.get("/me", response_model=UserOut)
def me(user: models.User = Depends(require_auth)):
    return user


@router.get("/users", response_model=List[UserOut])
def list_users(_: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(models.User).order_by(models.User.id).all()


@router.post("/users", response_model=UserOut)
def create_user(data: CreateUserRequest, _: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.username == data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Username '{data.username}' is already taken.")
    if data.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, operator, or viewer.")
    user = models.User(
        username=data.username,
        email=data.email,
        password_hash=_store_hash(data.password),
        role=data.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    data: UpdateUserRequest,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.id == current_user.id and data.role and data.role != "admin":
        raise HTTPException(status_code=400, detail="You cannot remove your own admin role.")
    if data.email is not None:
        user.email = data.email
    if data.role is not None:
        if data.role not in ("admin", "operator", "viewer"):
            raise HTTPException(status_code=400, detail="Invalid role.")
        user.role = data.role
    if data.is_active is not None:
        if not data.is_active:
            db.query(models.UserSession).filter(models.UserSession.user_id == user_id).delete()
        user.is_active = data.is_active
    if data.password:
        user.password_hash = _store_hash(data.password)
        # Invalidate all sessions on password change
        db.query(models.UserSession).filter(models.UserSession.user_id == user_id).delete()
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    db.delete(user)
    db.commit()
    return {"status": "deleted"}
