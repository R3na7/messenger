"""Client-side models for user and message display."""
from dataclasses import dataclass
from datetime import datetime


@dataclass
class User:
    id: int
    login: str
    nickname: str


@dataclass
class ChatMessage:
    id: int
    sender_id: int
    recipient_id: int
    text: str
    created_at: datetime
