"""Server configuration values."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = f"sqlite:///{BASE_DIR / 'secure_chat.db'}"
TOKEN_EXPIRY_MINUTES = 60 * 24
