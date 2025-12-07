"""HTTP API client for interacting with the secure chat server."""
from typing import Any, Dict, List, Optional

import requests

from .storage import get_token


class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        token = get_token()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def register(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = requests.post(f"{self.base_url}/auth/register", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def login(self, login: str, password: str) -> Dict[str, Any]:
        resp = requests.post(f"{self.base_url}/auth/login", json={"login": login, "password": password}, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def list_users(self, nickname: Optional[str] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if nickname:
            params["nickname"] = nickname
        resp = requests.get(f"{self.base_url}/users", params=params, headers=self._headers(), timeout=10)
        resp.raise_for_status()
        return resp.json()

    def get_public_key(self, user_id: int) -> str:
        resp = requests.get(f"{self.base_url}/users/{user_id}/public_key", headers=self._headers(), timeout=10)
        resp.raise_for_status()
        return resp.json()["public_key_pem"]

    def send_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = requests.post(f"{self.base_url}/messages/private", json=payload, headers=self._headers(), timeout=10)
        resp.raise_for_status()
        return resp.json()

    def get_messages(self, peer_id: int, after_message_id: int = 0) -> List[Dict[str, Any]]:
        resp = requests.get(
            f"{self.base_url}/messages/private",
            params={"peer_id": peer_id, "after_message_id": after_message_id},
            headers=self._headers(),
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def change_password(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = requests.post(
            f"{self.base_url}/auth/change_password", json=payload, headers=self._headers(), timeout=10
        )
        resp.raise_for_status()
        return resp.json()
