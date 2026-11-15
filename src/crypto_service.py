"""Cryptographic primitives: RSA-OAEP, RSA-PSS, SHA-256, bcrypt, AES-256-GCM (key wrapping)."""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone

import bcrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


RSA_KEY_SIZE = 2048
BCRYPT_ROUNDS = 12

# Election private keys at rest: AES-256-GCM, key derived with PBKDF2-HMAC-SHA256 from a server secret.
KEY_WRAP_PREFIX = "aes256gcm-pbkdf2"
KEY_WRAP_ITERATIONS = 200_000
_KEY_WRAP_AAD = b"securevote:election-private-key:v1"


def _derive_wrap_key(secret: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(secret.encode("utf-8"))


def is_wrapped_private_key(stored: str) -> bool:
    return stored.startswith(KEY_WRAP_PREFIX + "$")


def wrap_private_key(private_pem: bytes, secret: str) -> str:
    """Encrypt a private key PEM for database storage.

    Format: ``aes256gcm-pbkdf2$<iterations>$<b64 salt>$<b64 nonce>$<b64 ciphertext+tag>``.
    A fresh random salt and 96-bit nonce are used for every key.
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_wrap_key(secret, salt, KEY_WRAP_ITERATIONS)
    ct = AESGCM(key).encrypt(nonce, private_pem, _KEY_WRAP_AAD)
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"{KEY_WRAP_PREFIX}${KEY_WRAP_ITERATIONS}${b64(salt)}${b64(nonce)}${b64(ct)}"


def unwrap_private_key(stored: str, secret: str) -> bytes:
    """Decrypt a stored private key. A plain PEM (pre-encryption database) is returned unchanged.

    Raises ``cryptography.exceptions.InvalidTag`` if the secret is wrong or the data was modified.
    """
    if not is_wrapped_private_key(stored):
        return stored.encode("utf-8")
    _prefix, iterations, salt_b64, nonce_b64, ct_b64 = stored.split("$")
    key = _derive_wrap_key(secret, base64.b64decode(salt_b64), int(iterations))
    return AESGCM(key).decrypt(base64.b64decode(nonce_b64), base64.b64decode(ct_b64), _KEY_WRAP_AAD)


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem) as UTF-8 PEM bytes."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def normalize_rsa_public_key_pem(pem_text: str) -> str:
    """Validate a client-supplied voter public key and return it as canonical SPKI PEM.

    Raises ``ValueError`` unless it is an RSA key of at least ``RSA_KEY_SIZE`` bits.
    """
    try:
        key = load_pem_public_key(pem_text.strip().encode("utf-8"))
    except Exception as exc:
        raise ValueError("not a PEM public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < RSA_KEY_SIZE:
        raise ValueError(f"an RSA public key of at least {RSA_KEY_SIZE} bits is required")
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def integrity_hash_for_encrypted_vote(encrypted_vote_b64: str) -> str:
    raw = base64.b64decode(encrypted_vote_b64, validate=True)
    return sha256_hex(raw)


def _submission_message(encrypted_vote_b64: str, timestamp: str) -> bytes:
    return encrypted_vote_b64.encode("utf-8") + b"|" + timestamp.encode("utf-8")


def sign_submission(encrypted_vote_b64: str, timestamp: str, voter_private_pem: bytes) -> str:
    """RSA-PSS with SHA-256 over UTF-8 (encrypted_vote_b64 || '|' || timestamp)."""
    key = load_pem_private_key(voter_private_pem, password=None)
    msg = _submission_message(encrypted_vote_b64, timestamp)
    sig = key.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


def verify_submission_signature(
    encrypted_vote_b64: str, timestamp: str, signature_b64: str, voter_public_pem: bytes
) -> bool:
    try:
        key = load_pem_public_key(voter_public_pem)
        sig = base64.b64decode(signature_b64, validate=True)
        msg = _submission_message(encrypted_vote_b64, timestamp)
        key.verify(
            sig,
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def encrypt_vote_plaintext(plaintext: bytes, election_public_pem: bytes) -> str:
    key = load_pem_public_key(election_public_pem)
    ct = key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.b64encode(ct).decode("ascii")


def decrypt_vote_ciphertext(encrypted_vote_b64: str, election_private_pem: bytes) -> bytes:
    key = load_pem_private_key(election_private_pem, password=None)
    raw = base64.b64decode(encrypted_vote_b64, validate=True)
    return key.decrypt(
        raw,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def parse_iso8601(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
