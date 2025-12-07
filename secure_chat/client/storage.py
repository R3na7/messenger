"""Local client storage for credentials and keys."""
import base64
import json
from pathlib import Path
from typing import Any, Dict, Optional


STORAGE_FILE = Path.home() / ".secure_chat_client.json"


def load_state() -> Dict[str, Any]:
    if STORAGE_FILE.exists():
        with STORAGE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(data: Dict[str, Any]) -> None:
    STORAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STORAGE_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def store_private_key(private_key: bytes) -> None:
    state = load_state()
    state["private_key"] = base64.b64encode(private_key).decode()
    save_state(state)


def load_private_key() -> Optional[bytes]:
    state = load_state()
    if "private_key" in state:
        return base64.b64decode(state["private_key"])
    return None


def store_auth(token: str, user: Dict[str, Any]) -> None:
    state = load_state()
    state["token"] = token
    state["user"] = user
    save_state(state)


def clear_auth() -> None:
    state = load_state()
    for key in ["token", "user", "private_key"]:
        state.pop(key, None)
    save_state(state)


def get_token() -> Optional[str]:
    return load_state().get("token")


def get_user() -> Optional[Dict[str, Any]]:
    return load_state().get("user")
