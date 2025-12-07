"""User listing and public key retrieval routes."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from . import schemas
from .auth import get_current_user_id
from .database import get_db
from .models import User

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=List[schemas.UserOut])
def list_users(db: Session = Depends(get_db), _: int = Depends(get_current_user_id)):
    return db.query(User).all()


@router.get("/{user_id}/public_key", response_model=schemas.PublicKeyOut)
def get_public_key(user_id: int, db: Session = Depends(get_db), _: int = Depends(get_current_user_id)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return schemas.PublicKeyOut(public_key_pem=user.public_key_pem)
