"""
crypto.py  –  All cryptographic operations for SecureShare
---------------------------------------------------------------------------
Implements the following:
  1. AES-256-CBC   – encrypt / decrypt file bytes
  2. RSA-2048 OAEP – encrypt / decrypt the AES key (key exchange)
  3. SHA-256        – create & verify a file fingerprint (tamper detection)
  4. PBKDF2         – hash passwords so they are never stored in plaintext
---------------------------------------------------------------------------
Only standard + pyca/cryptography imports – no extra dependencies.
"""

import os, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as ap

# ── 1. AES-256-CBC ──────────────────────────────────────────────────────────

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt bytes with AES-256-CBC.  Returns IV (16 B) + ciphertext."""
    iv = os.urandom(16)
    p  = padding.PKCS7(128).padder()
    ct = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + ct.update(p.update(data) + p.finalize()) + ct.finalize()

def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypt IV+ciphertext produced by aes_encrypt."""
    iv, ct = blob[:16], blob[16:]
    dc = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    u  = padding.PKCS7(128).unpadder()
    return u.update(dc.update(ct) + dc.finalize()) + u.finalize()

def new_aes_key() -> bytes:
    return os.urandom(32)

# ── 2. RSA-2048 OAEP key exchange ───────────────────────────────────────────

def generate_rsa_keypair():
    """Return (private_pem_str, public_pem_str) for a fresh 2048-bit RSA key."""
    priv = rsa.generate_private_key(65537, 2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem

def rsa_encrypt(pub_pem: str, data: bytes) -> bytes:
    """Encrypt small data (e.g. a 32-byte AES key) with an RSA public key."""
    pub = serialization.load_pem_public_key(pub_pem.encode())
    return pub.encrypt(data, ap.OAEP(ap.MGF1(hashes.SHA256()), hashes.SHA256(), None))

def rsa_decrypt(priv_pem: str, data: bytes) -> bytes:
    """Decrypt data encrypted with rsa_encrypt using the RSA private key."""
    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    return priv.decrypt(data, ap.OAEP(ap.MGF1(hashes.SHA256()), hashes.SHA256(), None))

# ── 3. SHA-256 fingerprint ───────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ── 4. PBKDF2 password hashing ───────────────────────────────────────────────

def hash_password(password: str) -> tuple[str, str]:
    """Hash a password.  Returns (salt_hex, hash_hex)."""
    salt = os.urandom(16)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex(), h.hex()

def check_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return h.hex() == hash_hex
