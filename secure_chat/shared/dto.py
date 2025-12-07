"""Shared data transfer object helpers."""
from dataclasses import dataclass
from datetime import datetime


@dataclass
class UserDTO:
    id: int
    login: str
    nickname: str


@dataclass
class MessageDTO:
    id: int
    sender_id: int
    recipient_id: int
    ciphertext: str
    nonce: str
    tag: str
    encrypted_key_for_current_user: str
    created_at: datetime
