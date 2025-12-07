# Secure Chat (End-to-End Encrypted Messenger)

This project provides a simple end-to-end encrypted messenger for local networks. It includes a FastAPI server, a console client, and a PyQt GUI client that encrypt/decrypt messages locally so the server never has access to plaintext.

## Features
- User registration/login with bcrypt password hashing and account lockout after repeated failures.
- Unique user nicknames (e.g., `@alice`).
- RSA key pairs generated on the client; private keys are encrypted client-side using PBKDF2 + AES-GCM.
- Messages encrypted with AES-GCM; symmetric keys are wrapped with RSA for sender and recipient.
- FastAPI REST API with SQLite persistence via SQLAlchemy.
- Basic security logging to `server/server.log`.
- PyQt6 GUI client with login/registration, search by nickname, encrypted private chats, and password change.

## Project Structure
```
secure_chat/
  server/
    main.py            # FastAPI entrypoint
    auth.py            # Registration/login and token validation
    messages.py        # Message endpoints
    users.py           # User listing and public key retrieval
    models.py          # SQLAlchemy models
    schemas.py         # Pydantic schemas
    database.py        # DB engine/session helpers
    config.py          # Server configuration
    logging_config.py  # Rotating file logging setup
  client/
    main.py            # Console application
    gui_main.py        # PyQt GUI entrypoint
    gui/               # GUI widgets and windows
    api.py             # HTTP client wrapper
    crypto.py          # Client-side cryptography
    storage.py         # Local storage for auth and keys
    models.py          # Simple dataclasses for display
  shared/
    dto.py             # Shared DTO definitions
    utils.py           # Password strength helpers
requirements.txt
README.md
```

## Prerequisites
- Python 3.10+

## Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the Server
```bash
uvicorn secure_chat.server.main:app --host 0.0.0.0 --port 8000
```
The SQLite database will be created automatically in `secure_chat/server/secure_chat.db`. Logs are written to `secure_chat/server/server.log`.

## Running the Console Client
```bash
python -m secure_chat.client.main
```
- Provide the server URL (e.g., `http://192.168.0.10:8000`).
- Use the menu to register, login, list users, and start private chats.
- Messages are encrypted client-side; the server stores only ciphertext and wrapped keys.

## Running the GUI Client
```bash
python -m secure_chat.client.gui_main
```
- On first launch, enter the server URL (e.g., `http://192.168.0.10:8000`).
- Use the login/registration tabs to authenticate; keys are generated and encrypted client-side.
- Search for users by nickname, start private chats, and send end-to-end encrypted messages.
- Open the Profile dialog to view a key fingerprint, change password (re-encrypts the private key), or log out.

## Security Notes
- Passwords must be at least 10 characters and cannot be common weak passwords.
- After 5 failed login attempts, accounts are locked for 10 minutes.
- Private keys never leave the client; only encrypted blobs are stored server-side.

## Development Notes
- Token authentication uses an in-memory store; restarting the server invalidates tokens.
- This reference implementation is designed for local/LAN demos and educational use.
