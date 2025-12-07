"""Client-side cryptographic helpers for end-to-end encryption."""
import base64
import json
import os
from dataclasses import dataclass
from typing import Tuple

import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class EncryptedPrivateKey:
    """Container for encrypted private key blob."""

    salt: bytes
    nonce: bytes
    tag: bytes
    ciphertext: bytes

    def to_blob(self) -> str:
        data = {
            "salt": base64.b64encode(self.salt).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "tag": base64.b64encode(self.tag).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
        }
        return base64.b64encode(json.dumps(data).encode()).decode()

    @staticmethod
    def from_blob(blob: str) -> "EncryptedPrivateKey":
        data = json.loads(base64.b64decode(blob).decode())
        return EncryptedPrivateKey(
            salt=base64.b64decode(data["salt"]),
            nonce=base64.b64decode(data["nonce"]),
            tag=base64.b64decode(data["tag"]),
            ciphertext=base64.b64decode(data["ciphertext"]),
        )


def generate_key_pair() -> Tuple[bytes, bytes]:
    """Generate an RSA key pair and return (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend())
    return kdf.derive(password.encode())


def encrypt_private_key(private_pem: bytes, password: str) -> EncryptedPrivateKey:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key_from_password(password, salt)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, private_pem, None)
    tag = ciphertext[-16:]
    ct_body = ciphertext[:-16]
    return EncryptedPrivateKey(salt=salt, nonce=nonce, tag=tag, ciphertext=ct_body)


def decrypt_private_key(blob: str, password: str) -> bytes:
    enc = EncryptedPrivateKey.from_blob(blob)
    key = derive_key_from_password(password, enc.salt)
    aes = AESGCM(key)
    plaintext = aes.decrypt(enc.nonce, enc.ciphertext + enc.tag, None)
    return plaintext


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def encrypt_message_for_peer(message: str, sender_private_pem: bytes, recipient_public_pem: bytes) -> dict:
    """Encrypt a message using AES-GCM and wrap the key for both users."""
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aes = AESGCM(aes_key)
    ciphertext = aes.encrypt(nonce, message.encode(), None)
    tag = ciphertext[-16:]
    ct_body = ciphertext[:-16]

    sender_private_key = serialization.load_pem_private_key(sender_private_pem, password=None, backend=default_backend())
    sender_public = sender_private_key.public_key()
    recipient_public = serialization.load_pem_public_key(recipient_public_pem, backend=default_backend())

    def encrypt_key(public_key) -> bytes:
        return public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    encrypted_key_for_sender = encrypt_key(sender_public)
    encrypted_key_for_recipient = encrypt_key(recipient_public)

    return {
        "ciphertext": base64.b64encode(ct_body).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "encrypted_key_for_sender": base64.b64encode(encrypted_key_for_sender).decode(),
        "encrypted_key_for_recipient": base64.b64encode(encrypted_key_for_recipient).decode(),
    }


def decrypt_message_from_peer(
    ciphertext_b64: str,
    nonce_b64: str,
    tag_b64: str,
    encrypted_key_b64: str,
    private_key_pem: bytes,
) -> str:
    """Decrypt a message using stored private key and message bundle."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_key_b64),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    aes = AESGCM(aes_key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64) + base64.b64decode(tag_b64)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
