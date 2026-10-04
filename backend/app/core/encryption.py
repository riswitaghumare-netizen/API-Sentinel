import base64
import re
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app.core.config import settings

# Initialize cipher
def _get_fernet_key(secret: str) -> bytes:
    try:
        # Check if already a valid Fernet key
        return secret.encode() if len(secret) == 44 and secret.endswith('=') else base64.urlsafe_b64encode(
            hash_key(secret)
        )
    except Exception:
        return base64.urlsafe_b64encode(secret.ljust(32)[:32].encode())

def hash_key(secret: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"api_sentinel_salt_2026",
        iterations=100000,
    )
    return kdf.derive(secret.encode())

_cipher_key = _get_fernet_key(settings.ENCRYPTION_KEY)
_cipher = Fernet(_cipher_key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypts a sensitive string (API Key, Bearer token, password) for at-rest storage."""
    if not plaintext:
        return ""
    encrypted_bytes = _cipher.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypts an at-rest encrypted string."""
    if not ciphertext:
        return ""
    try:
        decrypted_bytes = _cipher.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except Exception:
        return "[ENCRYPTION_DECRYPTION_ERROR]"


def mask_secret(secret: str, visible_prefix: int = 3, visible_suffix: int = 3) -> str:
    """Masks secret strings for UI and logs (e.g. sk-live-***xyz)."""
    if not secret:
        return ""
    length = len(secret)
    if length <= 6:
        return "******"
    if length <= 10:
        return f"{secret[:2]}****{secret[-2:]}"
    return f"{secret[:visible_prefix]}****{secret[-visible_suffix:]}"


# Patterns for sensitive evidence redaction
SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{15,})'), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(api[_-]?key["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-\.]{8,})(["\']?)'), r'\1[REDACTED_API_KEY]\3'),
    (re.compile(r'(?i)(password["\']?\s*[:=]\s*["\']?)([^"\'\s]{3,})(["\']?)'), r'\1[REDACTED_PASSWORD]\3'),
    (re.compile(r'(?i)(authorization:\s*)([^\r\n]+)'), r'\1[REDACTED_AUTH_HEADER]'),
    (re.compile(r'(?i)(client_secret["\']?\s*[:=]\s*["\']?)([^"\'\s]{6,})(["\']?)'), r'\1[REDACTED_SECRET]\3'),
]


def redact_evidence(evidence_text: str) -> str:
    """Redacts known token, key, and password formats from raw HTTP evidence."""
    if not evidence_text:
        return ""
    redacted = evidence_text
    for pattern, replacement in SENSITIVE_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
