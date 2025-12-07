"""Message-related API routes."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from . import schemas
from .auth import get_current_user_id
from .database import get_db
from .logging_config import configure_logging
from .models import Message, User

router = APIRouter(prefix="/messages", tags=["messages"])
logger = configure_logging()


def _get_user(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/private")
def send_private_message(
    payload: schemas.MessageCreate,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
):
    sender = _get_user(db, current_user_id)
    recipient = _get_user(db, payload.recipient_id)

    message = Message(
        sender_id=sender.id,
        recipient_id=recipient.id,
        ciphertext=payload.ciphertext.encode(),
        nonce=payload.nonce.encode(),
        tag=payload.tag.encode(),
        encrypted_key_for_recipient=payload.encrypted_key_for_recipient.encode(),
        encrypted_key_for_sender=payload.encrypted_key_for_sender.encode(),
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    logger.info(
        "MESSAGE_SENT sender_id=%s recipient_id=%s message_id=%s",
        sender.id,
        recipient.id,
        message.id,
    )
    return {"message": "Message stored", "id": message.id}


@router.get("/private", response_model=List[schemas.MessageOut])
def get_private_messages(
    peer_id: int,
    after_message_id: int = 0,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
):
    _get_user(db, peer_id)
    messages = (
        db.query(Message)
        .filter(
            Message.id > after_message_id,
            ((Message.sender_id == current_user_id) & (Message.recipient_id == peer_id))
            | ((Message.sender_id == peer_id) & (Message.recipient_id == current_user_id)),
        )
        .order_by(Message.id)
        .all()
    )

    results: List[schemas.MessageOut] = []
    for msg in messages:
        encrypted_key = (
            msg.encrypted_key_for_sender if msg.sender_id == current_user_id else msg.encrypted_key_for_recipient
        )
        results.append(
            schemas.MessageOut(
                id=msg.id,
                sender_id=msg.sender_id,
                recipient_id=msg.recipient_id,
                ciphertext=msg.ciphertext.decode(),
                nonce=msg.nonce.decode(),
                tag=msg.tag.decode(),
                encrypted_key_for_current_user=encrypted_key.decode(),
                created_at=msg.created_at,
            )
        )
    return results
