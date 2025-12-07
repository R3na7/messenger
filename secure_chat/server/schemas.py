"""Pydantic schemas for request and response bodies."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    login: str
    password_hash: str
    nickname: str
    public_key_pem: str
    encrypted_private_key: str


class LoginRequest(BaseModel):
    login: str
    password: str


class UserOut(BaseModel):
    id: int
    login: str
    nickname: str

    class Config:
        orm_mode = True


class LoginResponse(BaseModel):
    token: str
    user: UserOut
    encrypted_private_key: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password_hash: str
    new_encrypted_private_key: str


class MessageCreate(BaseModel):
    recipient_id: int
    ciphertext: str
    nonce: str
    tag: str
    encrypted_key_for_recipient: str
    encrypted_key_for_sender: str


class MessageOut(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    ciphertext: str
    nonce: str
    tag: str
    encrypted_key_for_current_user: str
    created_at: datetime

    class Config:
        orm_mode = True


class PublicKeyOut(BaseModel):
    public_key_pem: str = Field(..., description="PEM encoded public key")
