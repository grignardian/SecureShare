"""
crypto.py  –  Cryptographic Engine & Portable Bundle Format for SecureShare
---------------------------------------------------------------------------
Implements:
  1. AES-256-CBC   – encrypt / decrypt file bytes with random 16-byte IV & PKCS7
  2. RSA-2048 OAEP – encrypt / decrypt the AES session key (key encapsulation)
  3. SHA-256       – compute & verify file integrity digests (tamper detection)
  4. PBKDF2        – salted password hashing (HMAC-SHA256, 200,000 iterations)
  5. .secureshare  – self-contained portable encrypted file bundle
"""

import os
import json
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as ap


BUNDLE_MAGIC = b"SECSHARE1"   # 9 bytes magic + format version


class BundleError(Exception):
    """Base error for .secureshare bundle parsing/decryption."""


class InvalidBundleError(BundleError):
    """Raised when a file is not a valid .secureshare bundle."""


class WrongKeyError(BundleError):
    """Raised when RSA private key cannot unwrap the bundle's AES session key."""


class TamperDetectedError(BundleError):
    """Raised when ciphertext corruption or SHA-256 mismatch is detected."""

    def __init__(self, message: str, expected_sha: str = "", actual_sha: str = ""):
        super().__init__(message)
        self.expected_sha = expected_sha
        self.actual_sha = actual_sha


# ── 1. AES-256-CBC ──────────────────────────────────────────────────────────

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt bytes with AES-256-CBC. Returns IV (16 B) + ciphertext."""
    iv = os.urandom(16)
    p  = padding.PKCS7(128).padder()
    ct = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + ct.update(p.update(data) + p.finalize()) + ct.finalize()


def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypt IV+ciphertext produced by aes_encrypt."""
    if len(blob) < 32 or (len(blob) - 16) % 16 != 0:
        raise ValueError("Ciphertext length is invalid or truncated.")
    iv, ct = blob[:16], blob[16:]
    dc = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    u  = padding.PKCS7(128).unpadder()
    return u.update(dc.update(ct) + dc.finalize()) + u.finalize()


def new_aes_key() -> bytes:
    return os.urandom(32)


# ── 2. RSA-2048 OAEP key exchange ───────────────────────────────────────────

def generate_rsa_keypair() -> tuple[str, str]:
    """Return (private_pem_str, public_pem_str) for a fresh 2048-bit RSA key."""
    priv = rsa.generate_private_key(65537, 2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return priv_pem, pub_pem


def validate_public_key(pub_pem: str) -> bool:
    """Return True if pub_pem is a valid PEM-encoded RSA public key."""
    try:
        serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        return True
    except Exception:
        return False


def validate_private_key(priv_pem: str) -> bool:
    """Return True if priv_pem is a valid unencrypted PEM-encoded private key."""
    try:
        serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
        return True
    except Exception:
        return False


def key_fingerprint(pub_pem: str) -> str:
    """Short human-readable SHA-256 fingerprint of a public key PEM."""
    digest = hashlib.sha256(pub_pem.strip().encode("utf-8")).hexdigest().upper()
    return ":".join(digest[i:i+4] for i in range(0, 16, 4))


def rsa_encrypt(pub_pem: str, data: bytes) -> bytes:
    """Encrypt small data (e.g. a 32-byte AES key) with an RSA public key."""
    pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    return pub.encrypt(data, ap.OAEP(ap.MGF1(hashes.SHA256()), hashes.SHA256(), None))


def rsa_decrypt(priv_pem: str, data: bytes) -> bytes:
    """Decrypt data encrypted with rsa_encrypt using the RSA private key."""
    priv = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
    return priv.decrypt(data, ap.OAEP(ap.MGF1(hashes.SHA256()), hashes.SHA256(), None))


# ── 3. SHA-256 fingerprint ──────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── 4. PBKDF2 password hashing ──────────────────────────────────────────────

def hash_password(password: str) -> tuple[str, str]:
    """Hash a password. Returns (salt_hex, hash_hex)."""
    salt = os.urandom(16)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), h.hex()


def check_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return h.hex() == hash_hex


# ── 5. Portable .secureshare File Bundle ────────────────────────────────────

def encrypt_file_bundle(
    plaintext: bytes,
    filename: str,
    recipient_pub_pem: str,
    recipient_name: str = "recipient",
    sender_name: str = "sender",
) -> tuple[bytes, dict]:
    """
    Encrypt a file into a self-contained .secureshare binary bundle.
    Returns (bundle_bytes, details_dict).

    Format:
      [9 bytes]  MAGIC ("SECSHARE1")
      [4 bytes]  header_len (uint32 big-endian)
      [header]   UTF-8 JSON metadata (filename, size, sender, recipient, sha256, enc_key)
      [payload]  Raw AES-256-CBC ciphertext (16-byte IV + encrypted blocks)
    """
    safe_name  = os.path.basename(filename) or "file"
    orig_hash  = sha256(plaintext)
    aes_key    = new_aes_key()
    ciphertext = aes_encrypt(plaintext, aes_key)
    enc_key    = rsa_encrypt(recipient_pub_pem, aes_key)

    header = {
        "filename":  safe_name,
        "size":      len(plaintext),
        "sender":    sender_name,
        "recipient": recipient_name,
        "sha256":    orig_hash,
        "enc_key":   enc_key.hex(),
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    bundle = BUNDLE_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext

    details = {
        "filename":        safe_name,
        "plaintext_size":  len(plaintext),
        "ciphertext_size": len(ciphertext),
        "bundle_size":     len(bundle),
        "sha256":          orig_hash,
        "header_offset":   len(BUNDLE_MAGIC) + 4 + len(header_bytes),
    }
    return bundle, details


def inspect_file_bundle(bundle_bytes: bytes) -> tuple[dict, bytes]:
    """
    Parse and validate the header of a .secureshare bundle without decrypting.
    Returns (header_dict, ciphertext_bytes).
    """
    magic_len = len(BUNDLE_MAGIC)
    if len(bundle_bytes) < magic_len + 4 or not bundle_bytes.startswith(BUNDLE_MAGIC):
        raise InvalidBundleError("Not a valid .secureshare encrypted file (invalid file signature).")

    header_len = struct.unpack(">I", bundle_bytes[magic_len:magic_len + 4])[0]
    header_end = magic_len + 4 + header_len
    if header_len == 0 or header_end > len(bundle_bytes):
        raise InvalidBundleError("Corrupted .secureshare header length.")

    try:
        header = json.loads(bundle_bytes[magic_len + 4:header_end].decode("utf-8"))
    except Exception as exc:
        raise InvalidBundleError(f"Corrupted .secureshare metadata header: {exc}") from exc

    required = ("filename", "size", "sha256", "enc_key")
    if not isinstance(header, dict) or any(k not in header for k in required):
        raise InvalidBundleError("Incomplete .secureshare metadata header.")

    header["filename"] = os.path.basename(str(header["filename"])) or "decrypted_file"
    ciphertext = bundle_bytes[header_end:]
    if not ciphertext:
        raise InvalidBundleError("Empty encrypted payload inside bundle.")

    return header, ciphertext


def decrypt_file_bundle(bundle_bytes: bytes, priv_pem: str) -> tuple[dict, bytes, str]:
    """
    Decrypt a .secureshare bundle using priv_pem and verify SHA-256 integrity.
    Returns (header_dict, plaintext_bytes, computed_sha256).
    Raises InvalidBundleError, WrongKeyError, or TamperDetectedError.
    """
    header, ciphertext = inspect_file_bundle(bundle_bytes)

    try:
        enc_key_bytes = bytes.fromhex(header["enc_key"])
    except ValueError as exc:
        raise InvalidBundleError("Invalid encrypted session key encoding in header.") from exc

    try:
        aes_key = rsa_decrypt(priv_pem, enc_key_bytes)
    except Exception as exc:
        target = header.get("recipient", "another recipient")
        raise WrongKeyError(
            f"Private key cannot unwrap this file's AES session key. "
            f"This file was encrypted for '{target}'."
        ) from exc

    try:
        plaintext = aes_decrypt(ciphertext, aes_key)
    except Exception as exc:
        raise TamperDetectedError(
            f"AES decryption failed — encrypted blocks or padding were corrupted ({exc}).",
            expected_sha=header["sha256"],
            actual_sha="",
        ) from exc

    actual_sha   = sha256(plaintext)
    expected_sha = header["sha256"]
    if actual_sha != expected_sha:
        raise TamperDetectedError(
            "SHA-256 integrity check failed — file contents do not match original digest!",
            expected_sha=expected_sha,
            actual_sha=actual_sha,
        )

    return header, plaintext, actual_sha
