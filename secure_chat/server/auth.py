"""Authentication and authorization utilities and routes."""
from datetime import datetime, timedelta
from typing import Dict, Optional

import bcrypt
import secrets
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from . import schemas
from .config import TOKEN_EXPIRY_MINUTES
from .database import get_db
from .logging_config import configure_logging
from .models import User

router = APIRouter(prefix="/auth", tags=["auth"])
logger = configure_logging()

# In-memory token store: token -> {"user_id": int, "expires": datetime}
TOKEN_STORE: Dict[str, Dict[str, datetime | int]] = {}


@router.post("/register")
def register(payload: schemas.RegisterRequest, db: Session = Depends(get_db)):
    existing_login = db.query(User).filter(User.login == payload.login).first()
    existing_nickname = db.query(User).filter(User.nickname == payload.nickname).first()
    if existing_login or existing_nickname:
        raise HTTPException(status_code=400, detail="Login or nickname already exists")

    user = User(
        login=payload.login,
        nickname=payload.nickname,
        password_hash=payload.password_hash,
        public_key_pem=payload.public_key_pem,
        encrypted_private_key=payload.encrypted_private_key.encode(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("REGISTER_SUCCESS login=%s nickname=%s", payload.login, payload.nickname)
    return {"message": "Registration successful"}


@router.post("/login", response_model=schemas.LoginResponse)
def login(payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    user: Optional[User] = db.query(User).filter(User.login == payload.login).first()
    if not user:
        logger.info("LOGIN_FAIL login=%s reason=not_found", payload.login)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.lock_until and user.lock_until > datetime.utcnow():
        logger.warning("ACCOUNT_BLOCKED login=%s locked_until=%s", payload.login, user.lock_until)
        raise HTTPException(status_code=403, detail=f"Account locked until {user.lock_until}")

    if not bcrypt.checkpw(payload.password.encode(), user.password_hash.encode()):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.lock_until = datetime.utcnow() + timedelta(minutes=10)
            logger.warning("ACCOUNT_BLOCKED login=%s locked_until=%s", payload.login, user.lock_until)
        db.commit()
        logger.info("LOGIN_FAIL login=%s reason=bad_password", payload.login)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.failed_login_attempts = 0
    user.lock_until = None
    db.commit()

    token = secrets.token_urlsafe(32)
    TOKEN_STORE[token] = {"user_id": user.id, "expires": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)}
    logger.info("LOGIN_SUCCESS login=%s user_id=%s", user.login, user.id)
    return schemas.LoginResponse(token=token, user=user, encrypted_private_key=user.encrypted_private_key.decode())


def _validate_token(header: str | None) -> int:
    if not header or not header.startswith("Bearer "):
        logger.warning("UNAUTHORIZED_ACCESS reason=missing_token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = header.split(" ", 1)[1]
    token_data = TOKEN_STORE.get(token)
    if not token_data:
        logger.warning("UNAUTHORIZED_ACCESS reason=unknown_token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if token_data["expires"] < datetime.utcnow():
        logger.warning("UNAUTHORIZED_ACCESS reason=expired_token")
        TOKEN_STORE.pop(token, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    return int(token_data["user_id"])


def get_current_user_id(authorization: str | None = Header(default=None)) -> int:
    """FastAPI dependency returning authenticated user's id."""
    return _validate_token(authorization)


@router.post("/change_password")
def change_password(
    payload: schemas.ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
):
    user: Optional[User] = db.query(User).filter(User.id == current_user_id).first()
    if not user:
        logger.warning("UNAUTHORIZED_ACCESS reason=user_not_found")
        raise HTTPException(status_code=401, detail="Unauthorized")

    if user.lock_until and user.lock_until > datetime.utcnow():
        logger.warning("ACCOUNT_BLOCKED login=%s locked_until=%s", user.login, user.lock_until)
        raise HTTPException(status_code=403, detail=f"Account locked until {user.lock_until}")

    if not bcrypt.checkpw(payload.old_password.encode(), user.password_hash.encode()):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.lock_until = datetime.utcnow() + timedelta(minutes=10)
            logger.warning("ACCOUNT_BLOCKED login=%s locked_until=%s", user.login, user.lock_until)
        db.commit()
        logger.info("PASSWORD_CHANGE_FAIL login=%s reason=bad_password", user.login)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.password_hash = payload.new_password_hash
    user.encrypted_private_key = payload.new_encrypted_private_key.encode()
    user.failed_login_attempts = 0
    user.lock_until = None
    db.commit()
    logger.info("PASSWORD_CHANGE_SUCCESS login=%s user_id=%s", user.login, user.id)
    return {"message": "Password changed"}
