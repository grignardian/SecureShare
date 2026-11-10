"""
crypto.py - Cryptographic Operations for SecureShare
----------------------------------------------------
Implements hybrid encryption as specified in the SecureShare synopsis:
1. AES-256-CBC with random 16-byte IV and PKCS7 padding (file encryption).
2. RSA-2048 OAEP with SHA-256 (encrypts the AES key and HMAC key).
3. HMAC-SHA256 over metadata and ciphertext (verifies integrity before decryption).
4. SHA-256 hash of the original file (verifies decrypted file integrity).

Encrypted bundle binary format:
  [9 bytes]   Magic signature ('SECSHARE1')
  [4 bytes]   Metadata header length (unsigned int, big-endian)
  [N bytes]   UTF-8 JSON metadata (filename, file_size, sha256, sender, recipient, encrypted_keys)
  [32 bytes]  HMAC-SHA256 tag computed over (Magic + HeaderLen + Metadata + IV + Ciphertext)
  [16+ bytes] 16-byte random IV + AES-256-CBC ciphertext
"""

import os
import json
import hmac
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding


FILE_MAGIC = b"SECSHARE1"
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB file size safety limit


# ---------------------------------------------------------------------------
# 1. Hashing and HMAC Functions
# ---------------------------------------------------------------------------

def compute_sha256(data):
    """Return the SHA-256 hex digest string of the given bytes."""
    digest = hashlib.sha256(data).hexdigest()
    return digest


def generate_aes_key():
    """Generate a random 256-bit (32-byte) AES key."""
    return os.urandom(32)


def generate_hmac_key():
    """Generate a separate random 256-bit (32-byte) HMAC key."""
    return os.urandom(32)


def compute_hmac(hmac_key, data):
    """Calculate a 32-byte HMAC-SHA256 authentication tag."""
    mac = hmac.new(hmac_key, data, hashlib.sha256)
    return mac.digest()


def verify_hmac(hmac_key, data, expected_tag):
    """Verify an HMAC-SHA256 tag safely using constant-time comparison."""
    actual_tag = compute_hmac(hmac_key, data)
    return hmac.compare_digest(actual_tag, expected_tag)


# ---------------------------------------------------------------------------
# 2. Symmetric Encryption (AES-256-CBC)
# ---------------------------------------------------------------------------

def encrypt_aes(plaintext_bytes, aes_key):
    """
    Encrypt bytes using AES-256-CBC with a random 16-byte IV and PKCS7 padding.
    Returns: IV (16 bytes) + ciphertext.
    """
    if len(aes_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    # Generate a fresh 16-byte Initialization Vector for every file
    iv = os.urandom(16)

    # Pad data so its length is a multiple of AES block size (128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    # Encrypt using AES-256-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV so decrypt_aes can read it later
    return iv + ciphertext


def decrypt_aes(iv_and_ciphertext, aes_key):
    """
    Decrypt IV + ciphertext using AES-256-CBC and remove PKCS7 padding.
    Returns: original unpadded bytes.
    """
    if len(aes_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    if len(iv_and_ciphertext) < 32:
        raise ValueError("Encrypted data is too short or incomplete.")

    # Extract 16-byte IV and remaining ciphertext
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length is corrupted (not aligned to block size).")

    # Decrypt using AES-256-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext_bytes


# ---------------------------------------------------------------------------
# 3. Asymmetric Key Wrapping (RSA-2048 OAEP)
# ---------------------------------------------------------------------------

def encrypt_rsa(public_key_pem, data_bytes):
    """Encrypt small key data using a recipient's RSA public key (OAEP + SHA-256)."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    encrypted_bytes = public_key.encrypt(
        data_bytes,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_bytes


def decrypt_rsa(private_key_pem, encrypted_bytes):
    """Decrypt key data using the user's RSA private key (OAEP + SHA-256)."""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_bytes
    except Exception:
        raise ValueError("RSA key decryption failed: Incorrect private key.")


# ---------------------------------------------------------------------------
# 4. Complete File Encryption & Decryption
# ---------------------------------------------------------------------------

def encrypt_file(
    input_path,
    output_path,
    recipient_public_key_pem,
    sender_name="",
    recipient_name="",
    overwrite=False
):
    """
    Encrypt a file locally before sending to the server:
    1. Read plaintext file and calculate its SHA-256 hash.
    2. Generate a random 32-byte AES key and a separate random 32-byte HMAC key.
    3. Encrypt the file with AES-256-CBC.
    4. Encrypt (AES key + HMAC key) together with the recipient's RSA public key.
    5. Calculate HMAC-SHA256 over metadata header + IV + ciphertext.
    6. Write the self-contained encrypted bundle to output_path.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError("Input file not found: " + str(input_path))

    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Output file cannot be the same as the input file.")

    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError("Output file already exists: " + str(output_path))

    file_size = os.path.getsize(input_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds maximum allowed size of 50 MB.")

    with open(input_path, "rb") as file_obj:
        plaintext_bytes = file_obj.read()

    # Step 1: Original SHA-256 hash for integrity verification after decryption
    original_sha256 = compute_sha256(plaintext_bytes)

    # Step 2: Generate random session keys
    aes_key = generate_aes_key()
    hmac_key = generate_hmac_key()

    # Step 3: Encrypt file data with AES-256-CBC
    iv_and_ciphertext = encrypt_aes(plaintext_bytes, aes_key)

    # Step 4: Encrypt AES key and HMAC key with recipient's RSA public key
    combined_keys = aes_key + hmac_key
    encrypted_keys = encrypt_rsa(recipient_public_key_pem, combined_keys)

    # Step 5: Build JSON metadata header
    original_filename = os.path.basename(input_path)
    metadata = {
        "filename": original_filename,
        "file_size": len(plaintext_bytes),
        "sha256": original_sha256,
        "sender": sender_name,
        "recipient": recipient_name,
        "encrypted_keys": encrypted_keys.hex()
    }
    metadata_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    header_len_bytes = struct.pack(">I", len(metadata_bytes))

    # Step 6: Calculate HMAC-SHA256 over header and ciphertext
    data_to_authenticate = FILE_MAGIC + header_len_bytes + metadata_bytes + iv_and_ciphertext
    hmac_tag = compute_hmac(hmac_key, data_to_authenticate)

    # Step 7: Combine everything into the encrypted file bundle
    bundle = (
        FILE_MAGIC +
        header_len_bytes +
        metadata_bytes +
        hmac_tag +
        iv_and_ciphertext
    )

    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "wb") as out_obj:
        out_obj.write(bundle)

    return {
        "filename": original_filename,
        "file_size": len(plaintext_bytes),
        "encrypted_size": len(bundle),
        "sha256": original_sha256,
        "output_path": output_path
    }


def decrypt_file(input_path, output_path, recipient_private_key_pem, overwrite=False):
    """
    Decrypt a downloaded encrypted file locally:
    1. Parse file format signature and metadata header.
    2. Decrypt (AES key + HMAC key) using recipient's RSA private key.
    3. Verify HMAC-SHA256 BEFORE decryption using hmac.compare_digest().
    4. Decrypt ciphertext using AES-256-CBC.
    5. Recalculate SHA-256 hash and verify it matches original metadata hash.
    6. Save restored file to output_path.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError("Encrypted file not found: " + str(input_path))

    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Output file cannot be the same as the input file.")

    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError("Output file already exists: " + str(output_path))

    with open(input_path, "rb") as file_obj:
        data = file_obj.read()

    magic_len = len(FILE_MAGIC)
    if len(data) < magic_len + 4 or not data.startswith(FILE_MAGIC):
        raise ValueError("Corrupted or invalid encrypted file (bad file signature).")

    header_len_bytes = data[magic_len:magic_len + 4]
    header_len = struct.unpack(">I", header_len_bytes)[0]

    header_end = magic_len + 4 + header_len
    hmac_end = header_end + 32

    # Must contain metadata, 32-byte HMAC, and at least 32 bytes for IV + 1 AES block
    if header_len == 0 or len(data) < hmac_end + 32:
        raise ValueError("Corrupted or truncated encrypted file.")

    metadata_bytes = data[magic_len + 4:header_end]
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception:
        raise ValueError("Corrupted encrypted file metadata header.")

    if not isinstance(metadata, dict) or "encrypted_keys" not in metadata or "sha256" not in metadata:
        raise ValueError("Incomplete encrypted file metadata.")

    hmac_tag = data[header_end:hmac_end]
    iv_and_ciphertext = data[hmac_end:]

    try:
        encrypted_keys_bytes = bytes.fromhex(metadata["encrypted_keys"])
    except ValueError:
        raise ValueError("Corrupted key encoding inside encrypted file.")

    # Step 1: Recover AES key and HMAC key using RSA private key
    combined_keys = decrypt_rsa(recipient_private_key_pem, encrypted_keys_bytes)
    if len(combined_keys) != 64:
        raise ValueError("Decrypted key bundle has invalid size.")

    aes_key = combined_keys[:32]
    hmac_key = combined_keys[32:]

    # Step 2: Verify HMAC BEFORE decrypting the ciphertext
    authenticated_data = FILE_MAGIC + header_len_bytes + metadata_bytes + iv_and_ciphertext
    if not verify_hmac(hmac_key, authenticated_data, hmac_tag):
        raise ValueError(
            "Security alert: HMAC verification failed! "
            "The file data or metadata was modified or corrupted."
        )

    # Step 3: Decrypt the file using AES-256-CBC
    try:
        plaintext_bytes = decrypt_aes(iv_and_ciphertext, aes_key)
    except Exception:
        raise ValueError("AES decryption failed: ciphertext or padding is corrupted.")

    # Step 4: Verify SHA-256 hash matches the original hash stored in metadata
    actual_sha256 = compute_sha256(plaintext_bytes)
    expected_sha256 = metadata["sha256"]
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ValueError(
            "Security alert: SHA-256 integrity check failed! "
            "Decrypted file does not match original checksum."
        )

    # Step 5: Save restored plaintext file
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "wb") as out_obj:
        out_obj.write(plaintext_bytes)

    return {
        "filename": metadata.get("filename", "decrypted_file"),
        "file_size": len(plaintext_bytes),
        "sha256": actual_sha256,
        "sender": metadata.get("sender", ""),
        "recipient": metadata.get("recipient", ""),
        "output_path": output_path
    }
