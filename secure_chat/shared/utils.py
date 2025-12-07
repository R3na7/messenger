"""Shared utility functions."""
import re
from typing import Iterable

PASSWORD_BLACKLIST = {
    "123456",
    "123456789",
    "password",
    "qwerty",
    "111111",
    "12345678",
}


def is_password_strong(password: str, min_length: int = 10) -> bool:
    """Return True if password meets simple strength requirements."""
    if len(password) < min_length:
        return False
    if password.lower() in PASSWORD_BLACKLIST:
        return False
    if re.fullmatch(r"\d+", password):
        return False
    return True
