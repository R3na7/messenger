"""Console client for the secure chat application."""
import sys
from typing import Dict, Optional

from . import api
from .crypto import (
    decrypt_message_from_peer,
    decrypt_private_key,
    encrypt_message_for_peer,
    encrypt_private_key,
    generate_key_pair,
    hash_password,
)
from .models import User
from .storage import clear_auth, get_token, get_user, load_private_key, store_auth, store_private_key
from ..shared.utils import is_password_strong


class ChatClient:
    """Interactive console client for sending and receiving encrypted messages."""

    def __init__(self, server_url: str):
        self.api = api.APIClient(server_url)
        self.private_key: Optional[bytes] = load_private_key()
        self.current_user = get_user()

    def register(self) -> None:
        print("=== Register ===")
        login = input("Login: ").strip()
        password = input("Password (min 10 chars): ").strip()
        nickname = input("Nickname (e.g. @alice): ").strip()

        if not is_password_strong(password):
            print("Password too weak or blacklisted.")
            return

        private_pem, public_pem = generate_key_pair()
        enc = encrypt_private_key(private_pem, password)
        payload = {
            "login": login,
            "password_hash": hash_password(password),
            "nickname": nickname,
            "public_key_pem": public_pem.decode(),
            "encrypted_private_key": enc.to_blob(),
        }
        try:
            self.api.register(payload)
            print("Registration successful. You can now log in.")
        except Exception as exc:  # noqa: BLE001
            print(f"Registration failed: {exc}")

    def login(self) -> bool:
        print("=== Login ===")
        login = input("Login: ").strip()
        password = input("Password: ").strip()
        try:
            response = self.api.login(login, password)
        except Exception as exc:  # noqa: BLE001
            print(f"Login failed: {exc}")
            return False

        try:
            private_key = decrypt_private_key(response["encrypted_private_key"], password)
        except Exception as exc:  # noqa: BLE001
            print(f"Could not decrypt private key: {exc}")
            return False

        self.private_key = private_key
        store_private_key(private_key)
        store_auth(response["token"], response["user"])
        self.current_user = response["user"]
        print(f"Welcome, {self.current_user['nickname']}!")
        return True

    def list_users(self) -> Dict[int, User]:
        try:
            users_raw = self.api.list_users()
        except Exception as exc:  # noqa: BLE001
            print(f"Could not fetch users: {exc}")
            return {}
        users = {u["id"]: User(**u) for u in users_raw}
        for u in users.values():
            print(f"- {u.id}: {u.nickname} ({u.login})")
        return users

    def start_chat(self):
        users = self.list_users()
        nickname = input("Enter recipient nickname (e.g. @bob): ").strip()
        peer = next((u for u in users.values() if u.nickname == nickname), None)
        if not peer:
            print("User not found.")
            return
        last_id = 0
        while True:
            print("\nChat commands: [s]end, [r]efresh, [b]ack")
            cmd = input("> ").strip().lower()
            if cmd == "b":
                break
            if cmd == "s":
                text = input("Message: ")
                self._send_message(peer, text)
            if cmd == "r":
                last_id = self._refresh_messages(peer, last_id)

    def _send_message(self, peer: User, text: str) -> None:
        if not self.private_key:
            print("No private key loaded.")
            return
        try:
            recipient_pub = self.api.get_public_key(peer.id).encode()
            bundle = encrypt_message_for_peer(text, self.private_key, recipient_pub)
            payload = {"recipient_id": peer.id, **bundle}
            self.api.send_message(payload)
            print("Message sent.")
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to send message: {exc}")

    def _refresh_messages(self, peer: User, last_id: int) -> int:
        if not self.private_key:
            print("No private key loaded.")
            return last_id
        try:
            messages = self.api.get_messages(peer.id, after_message_id=last_id)
        except Exception as exc:  # noqa: BLE001
            print(f"Could not fetch messages: {exc}")
            return last_id
        for msg in messages:
            text = decrypt_message_from_peer(
                msg["ciphertext"], msg["nonce"], msg["tag"], msg["encrypted_key_for_current_user"], self.private_key
            )
            direction = "(you)" if msg["sender_id"] == self.current_user["id"] else peer.nickname
            timestamp = msg["created_at"][11:16]
            print(f"[{timestamp}] {direction}: {text}")
            last_id = msg["id"]
        if not messages:
            print("No new messages.")
        return last_id

    def logout(self):
        clear_auth()
        self.private_key = None
        self.current_user = None
        print("Logged out.")


def main():
    print("Secure Chat Client")
    server_url = input("Server URL (e.g. http://127.0.0.1:8000): ").strip()
    client = ChatClient(server_url)

    while True:
        print("\nMenu: [r]egister, [l]ogin, [q]uit")
        choice = input("> ").strip().lower()
        if choice == "q":
            sys.exit(0)
        if choice == "r":
            client.register()
        if choice == "l":
            if client.login():
                while get_token():
                    print("\nUser menu: [u]sers, [c]hat, [o]logout")
                    sub = input("> ").strip().lower()
                    if sub == "o":
                        client.logout()
                        break
                    if sub == "u":
                        client.list_users()
                    if sub == "c":
                        client.start_chat()


if __name__ == "__main__":
    main()
