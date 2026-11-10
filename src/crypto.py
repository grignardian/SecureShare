"""
crypto.py - Core Cryptographic Operations for SecureShare
---------------------------------------------------------
This module provides simple functions for:
1. AES-256-CBC: Fast file encryption using a symmetric session key.
2. RSA-2048 OAEP: Asymmetric encryption to securely protect the AES key.
3. SHA-256: Hashing the original file to detect tampering or corruption.

Format of .secureshare file:
[9 bytes Magic: 'SECSHARE1']
[4 bytes Header Length (integer)]
[JSON Header: original filename, file hash, encrypted AES key]
[Ciphertext: 16-byte IV + encrypted data]
"""

import os
import json
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding


# Signature marker to identify SecureShare encrypted files
FILE_MAGIC = b"SECSHARE1"


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class InvalidFileError(CryptoError):
    """Raised when the input file is not a valid SecureShare file."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails due to an incorrect private key."""
    pass


class IntegrityError(CryptoError):
    """Raised when SHA-256 hash check fails (file tampered or corrupted)."""
    pass


# ---------------------------------------------------------------------------
# 1. Hashing & Key Generation
# ---------------------------------------------------------------------------

def compute_sha256(data: bytes) -> str:
    """Calculate the SHA-256 hex digest of data for tamper detection."""
    return hashlib.sha256(data).hexdigest()


def generate_aes_key() -> bytes:
    """Generate a random 256-bit (32 bytes) AES symmetric key."""
    return os.urandom(32)


# ---------------------------------------------------------------------------
# 2. Symmetric Encryption (AES-256-CBC)
# ---------------------------------------------------------------------------

def encrypt_aes(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data bytes using AES-256-CBC.
    Returns: 16-byte IV + encrypted ciphertext.
    """
    # 16-byte random Initialization Vector (IV)
    iv = os.urandom(16)

    # Pad data to 128-bit (16 bytes) block size using PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt with AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV to ciphertext so it can be used during decryption
    return iv + ciphertext


def decrypt_aes(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt IV + ciphertext using AES-256-CBC.
    Returns: original unpadded plaintext bytes.
    """
    if len(iv_and_ciphertext) < 32:
        raise DecryptionError("Encrypted data is too short or invalid.")

    # Extract IV (first 16 bytes) and ciphertext
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    # Decrypt with AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext


# ---------------------------------------------------------------------------
# 3. Asymmetric Encryption (RSA-2048 OAEP)
# ---------------------------------------------------------------------------

def encrypt_rsa(public_key_pem: str, data: bytes) -> bytes:
    """Encrypt small data (such as the 32-byte AES key) using RSA public key."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    encrypted_data = public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data


def decrypt_rsa(private_key_pem: str, encrypted_data: bytes) -> bytes:
    """Decrypt data using RSA private key."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )
    decrypted_data = private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data


# ---------------------------------------------------------------------------
# 4. File-Level Operations (Encrypt & Decrypt Files)
# ---------------------------------------------------------------------------

def encrypt_file(input_path: str, output_path: str, recipient_public_key_pem: str) -> dict:
    """
    Encrypt a file using hybrid encryption (AES-256 + RSA-2048):
    1. Read original file.
    2. Compute SHA-256 checksum for integrity check.
    3. Generate a random AES-256 key and encrypt the file content.
    4. Encrypt the AES key with recipient's RSA public key.
    5. Package header and ciphertext, then write to output_path.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Read the original file
    with open(input_path, "rb") as f:
        file_bytes = f.read()

    # Step 1: Compute SHA-256 integrity hash
    original_hash = compute_sha256(file_bytes)

    # Step 2: Encrypt file content with a fresh AES-256 key
    aes_key = generate_aes_key()
    ciphertext = encrypt_aes(file_bytes, aes_key)

    # Step 3: Encrypt the AES key with recipient's RSA public key
    encrypted_aes_key = encrypt_rsa(recipient_public_key_pem, aes_key)

    # Step 4: Prepare JSON header with metadata
    original_filename = os.path.basename(input_path)
    header = {
        "filename": original_filename,
        "file_size": len(file_bytes),
        "sha256": original_hash,
        "encrypted_key": encrypted_aes_key.hex()
    }
    header_bytes = json.dumps(header).encode("utf-8")

    # Step 5: Build final bundle: Magic + Header Size + Header JSON + Ciphertext
    bundle = (
        FILE_MAGIC +
        struct.pack(">I", len(header_bytes)) +
        header_bytes +
        ciphertext
    )

    # Ensure output directory exists and write file
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "wb") as f:
        f.write(bundle)

    return {
        "filename": original_filename,
        "original_size": len(file_bytes),
        "encrypted_size": len(bundle),
        "sha256": original_hash,
        "output_path": output_path
    }


def decrypt_file(input_path: str, output_path: str, recipient_private_key_pem: str) -> dict:
    """
    Decrypt a .secureshare file:
    1. Read and validate file header.
    2. Decrypt the AES key using the private key.
    3. Decrypt the file ciphertext with AES.
    4. Verify SHA-256 checksum against the header.
    5. Save restored file to output_path.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    with open(input_path, "rb") as f:
        data = f.read()

    # Validate file magic signature
    magic_len = len(FILE_MAGIC)
    if len(data) < magic_len + 4 or not data.startswith(FILE_MAGIC):
        raise InvalidFileError("The selected file is not a valid SecureShare encrypted file.")

    # Extract header length and header bytes
    header_length = struct.unpack(">I", data[magic_len:magic_len + 4])[0]
    header_end = magic_len + 4 + header_length

    if header_end > len(data):
        raise InvalidFileError("File header is corrupted or incomplete.")

    try:
        header_json = data[magic_len + 4:header_end].decode("utf-8")
        header = json.loads(header_json)
    except Exception as e:
        raise InvalidFileError(f"Failed to read file metadata header: {e}")

    # Extract encrypted AES key and ciphertext
    encrypted_key_hex = header.get("encrypted_key")
    expected_sha256 = header.get("sha256")
    original_filename = header.get("filename", "decrypted_file")
    ciphertext = data[header_end:]

    if not encrypted_key_hex or not expected_sha256 or not ciphertext:
        raise InvalidFileError("File is missing required encryption metadata.")

    # Step 1: Decrypt the AES key with RSA private key
    try:
        encrypted_key_bytes = bytes.fromhex(encrypted_key_hex)
        aes_key = decrypt_rsa(recipient_private_key_pem, encrypted_key_bytes)
    except Exception as e:
        raise DecryptionError(
            "Decryption failed: Incorrect private key. "
            "Only the recipient who owns the matching private key can decrypt this file."
        )

    # Step 2: Decrypt the file contents with the recovered AES key
    try:
        decrypted_bytes = decrypt_aes(ciphertext, aes_key)
    except Exception as e:
        raise IntegrityError(f"Decryption failed: Ciphertext or padding was corrupted ({e}).")

    # Step 3: Verify SHA-256 checksum to ensure file was not altered
    actual_sha256 = compute_sha256(decrypted_bytes)
    if actual_sha256 != expected_sha256:
        raise IntegrityError(
            f"Integrity check failed! "
            f"Expected SHA-256: {expected_sha256}, but got: {actual_sha256}. "
            f"The file has been tampered with or corrupted."
        )

    # Step 4: Save decrypted file
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "wb") as f:
        f.write(decrypted_bytes)

    return {
        "filename": original_filename,
        "restored_size": len(decrypted_bytes),
        "sha256": actual_sha256,
        "output_path": output_path
    }
