"""Application controller logic for the PyQt GUI client."""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from .. import api
from ..crypto import (
    decrypt_message_from_peer,
    decrypt_private_key,
    encrypt_message_for_peer,
    encrypt_private_key,
    generate_key_pair,
    hash_password,
)
from ..storage import clear_auth, get_server_url, get_user, load_private_key, store_auth, store_private_key, store_server_url
from ...shared.utils import is_password_strong


class ChatController:
    """Encapsulates network calls and cryptographic operations for the GUI."""

    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or get_server_url() or ""
        if self.base_url:
            self.api = api.APIClient(self.base_url)
        else:
            self.api = None
        self.user = get_user()
        self.private_key: Optional[bytes] = load_private_key()
        self.public_key_pem: Optional[bytes] = None
        self.last_message_ids: Dict[int, int] = {}
        self.public_key_cache: Dict[int, bytes] = {}

    def set_base_url(self, url: str) -> None:
        self.base_url = url.rstrip("/")
        store_server_url(self.base_url)
        self.api = api.APIClient(self.base_url)

    def ensure_ready(self) -> None:
        if not self.api:
            raise RuntimeError("Server URL not configured")

    def register(self, login: str, password: str, nickname: str) -> Dict[str, str]:
        self.ensure_ready()
        if not is_password_strong(password):
            raise ValueError("Password does not meet policy requirements")
        private_pem, public_pem = generate_key_pair()
        enc = encrypt_private_key(private_pem, password)
        payload = {
            "login": login,
            "password_hash": hash_password(password),
            "nickname": nickname,
            "public_key_pem": public_pem.decode(),
            "encrypted_private_key": enc.to_blob(),
        }
        return self.api.register(payload)

    def login(self, login: str, password: str) -> Dict[str, str]:
        self.ensure_ready()
        response = self.api.login(login, password)
        private_key = decrypt_private_key(response["encrypted_private_key"], password)
        self.private_key = private_key
        store_private_key(private_key)
        store_auth(response["token"], response["user"])
        self.user = response["user"]
        self.public_key_pem = None
        self.last_message_ids = {}
        return response

    def logout(self) -> None:
        clear_auth()
        self.private_key = None
        self.user = None
        self.public_key_pem = None
        self.last_message_ids = {}

    def list_users(self, nickname: Optional[str] = None) -> List[Dict[str, str]]:
        self.ensure_ready()
        users = self.api.list_users(nickname=nickname)
        for u in users:
            if "public_key_pem" in u:
                self.public_key_cache[u["id"]] = u["public_key_pem"].encode()
        return users

    def get_public_key_for_user(self, user_id: int) -> bytes:
        if user_id in self.public_key_cache:
            return self.public_key_cache[user_id]
        self.ensure_ready()
        public_pem = self.api.get_public_key(user_id).encode()
        self.public_key_cache[user_id] = public_pem
        if self.user and user_id == self.user.get("id"):
            self.public_key_pem = public_pem
        return public_pem

    def send_message(self, peer_id: int, message: str) -> Dict[str, str]:
        if not self.private_key:
            raise RuntimeError("Private key not loaded")
        recipient_pub = self.get_public_key_for_user(peer_id)
        bundle = encrypt_message_for_peer(message, self.private_key, recipient_pub)
        payload = {"recipient_id": peer_id, **bundle}
        return self.api.send_message(payload)

    def fetch_messages(self, peer_id: int) -> List[Dict[str, str]]:
        if not self.private_key:
            raise RuntimeError("Private key not loaded")
        after_id = self.last_message_ids.get(peer_id, 0)
        messages = self.api.get_messages(peer_id, after_message_id=after_id)
        results: List[Dict[str, str]] = []
        for msg in messages:
            plaintext = decrypt_message_from_peer(
                msg["ciphertext"], msg["nonce"], msg["tag"], msg["encrypted_key_for_current_user"], self.private_key
            )
            msg_copy = dict(msg)
            msg_copy["plaintext"] = plaintext
            results.append(msg_copy)
            self.last_message_ids[peer_id] = msg["id"]
        return results

    def change_password(self, old_password: str, new_password: str) -> Dict[str, str]:
        if not self.private_key:
            raise RuntimeError("Private key not loaded")
        if not is_password_strong(new_password):
            raise ValueError("New password does not meet policy")
        enc = encrypt_private_key(self.private_key, new_password)
        payload = {
            "old_password": old_password,
            "new_password_hash": hash_password(new_password),
            "new_encrypted_private_key": enc.to_blob(),
        }
        return self.api.change_password(payload)

    def fingerprint(self) -> str:
        if self.public_key_pem is None:
            if not self.user:
                return ""
            try:
                self.public_key_pem = self.get_public_key_for_user(self.user["id"])
            except Exception:  # noqa: BLE001
                return ""
        digest = hashlib.sha256(self.public_key_pem).hexdigest()
        return f"{digest[:16]}…"


__all__ = ["ChatController", "is_password_strong"]
