"""
crypto.py - Cryptographic Operations for SecureShare
----------------------------------------------------
Implements hybrid encryption for offline file encryption/decryption:
1. AES-256-GCM authenticated encryption (file encryption + integrity).
2. RSA-2048 OAEP with SHA-256 (wraps the 32-byte AES key).
3. SHA-256 hash of the original plaintext (post-decrypt verification).

Encrypted bundle binary format (version 2):
  [9 bytes]   Magic signature ('SECSHARE2')
  [4 bytes]   Metadata JSON length (unsigned int, big-endian)
  [N bytes]   UTF-8 JSON metadata: {format_version, filename, file_size, sha256, encrypted_key}
  [12 bytes]  GCM nonce
  [remaining] AES-256-GCM ciphertext + 16-byte GCM authentication tag
"""

import os
import json
import struct
import hashlib
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding


FILE_MAGIC = b"SECSHARE2"
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB file size safety limit
GCM_NONCE_SIZE = 12  # 96-bit nonce recommended for AES-GCM
MAX_HEADER_SIZE = 64 * 1024


# ---------------------------------------------------------------------------
# 1. Hashing Utilities
# ---------------------------------------------------------------------------

def compute_sha256(data):
    """Return the SHA-256 hex digest string of the given bytes."""
    digest = hashlib.sha256(data).hexdigest()
    return digest


def generate_aes_key():
    """Generate a random 256-bit (32-byte) AES key."""
    return os.urandom(32)


# ---------------------------------------------------------------------------
# 2. Symmetric Encryption (AES-256-GCM)
# ---------------------------------------------------------------------------

def encrypt_aes_gcm(plaintext_bytes, aes_key, aad=None):
    """
    Encrypt bytes using AES-256-GCM with a random 12-byte nonce.
    Returns: nonce (12 bytes) + ciphertext + GCM auth tag (16 bytes).
    """
    if len(aes_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    # Generate a fresh 12-byte nonce for every encryption
    nonce = os.urandom(GCM_NONCE_SIZE)

    aesgcm = AESGCM(aes_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    # Prepend nonce so decrypt_aes_gcm can read it later
    return nonce, ciphertext_and_tag


def decrypt_aes_gcm(nonce, ciphertext_and_tag, aes_key, aad=None):
    """
    Decrypt nonce + ciphertext + GCM tag using AES-256-GCM.
    Raises InvalidTag (wrapped as ValueError) on authentication failure.
    Returns: original plaintext bytes.
    """
    if len(aes_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("GCM nonce must be 12 bytes.")

    # ciphertext must be at least 16 bytes (the GCM tag alone)
    if len(ciphertext_and_tag) < 16:
        raise ValueError("Encrypted data is too short or incomplete.")

    aesgcm = AESGCM(aes_key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
    except Exception:
        raise ValueError(
            "AES-GCM authentication failed: "
            "the file data or key is corrupted or incorrect."
        )

    return plaintext_bytes


# ---------------------------------------------------------------------------
# 3. Asymmetric Key Wrapping (RSA-2048 OAEP)
# ---------------------------------------------------------------------------

def encrypt_rsa(public_key_pem, data_bytes):
    """Encrypt small key data using a recipient's RSA public key (OAEP + SHA-256)."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not hasattr(public_key, "key_size") or public_key.key_size < 2048:
        raise ValueError("Recipient key must be an RSA key of at least 2048 bits.")
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
    """
    Decrypt key data using the user's RSA private key (OAEP + SHA-256).
    Accepts either a PEM string or a loaded private key object.
    """
    try:
        # Accept either a PEM string or an already-loaded private key object
        if isinstance(private_key_pem, str):
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=None
            )
        elif isinstance(private_key_pem, bytes):
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
        else:
            # Assume it is already a loaded private key object
            private_key = private_key_pem

        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_bytes
    except ValueError:
        raise
    except Exception:
        raise ValueError("RSA key decryption failed: Incorrect private key.")


# ---------------------------------------------------------------------------
# 4. Bundle Metadata Helpers
# ---------------------------------------------------------------------------

def _sanitize_filename(filename):
    """
    Sanitize a filename from bundle metadata to prevent path traversal.
    Returns only the basename, stripping any directory components.
    """
    # os.path.basename handles both Unix and Windows separators
    sanitized = os.path.basename(filename.replace("\\", "/"))
    # Reject empty filenames after sanitization
    if not sanitized:
        sanitized = "decrypted_file"
    return sanitized


def _read_bundle_metadata(data):
    """
    Parse the magic, header length, and JSON metadata from raw bundle bytes.
    Returns: (metadata_dict, metadata_end_offset)
    Raises ValueError on any format or integrity issue.
    """
    magic_len = len(FILE_MAGIC)

    if len(data) < magic_len + 4 or not data.startswith(FILE_MAGIC):
        raise ValueError("Corrupted or invalid encrypted file (bad file signature).")

    header_len_bytes = data[magic_len:magic_len + 4]
    header_len = struct.unpack(">I", header_len_bytes)[0]

    metadata_end = magic_len + 4 + header_len

    if header_len == 0 or header_len > MAX_HEADER_SIZE or len(data) < metadata_end + GCM_NONCE_SIZE + 16:
        raise ValueError("Corrupted or truncated encrypted file.")

    metadata_bytes = data[magic_len + 4:metadata_end]
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception:
        raise ValueError("Corrupted encrypted file metadata header.")

    if not isinstance(metadata, dict):
        raise ValueError("Incomplete encrypted file metadata.")

    required_keys = {"format_version", "encrypted_key", "sha256", "filename", "file_size"}
    if not required_keys.issubset(metadata.keys()):
        raise ValueError("Incomplete encrypted file metadata.")

    if metadata.get("format_version") != 2:
        raise ValueError("Unsupported bundle format version.")

    if (not isinstance(metadata["filename"], str) or len(metadata["filename"]) > 255
            or not isinstance(metadata["file_size"], int) or metadata["file_size"] < 0
            or metadata["file_size"] > MAX_FILE_SIZE
            or not isinstance(metadata["sha256"], str) or len(metadata["sha256"]) != 64
            or not isinstance(metadata["encrypted_key"], str)):
        raise ValueError("Invalid encrypted file metadata.")
    if len(data) != metadata_end + GCM_NONCE_SIZE + metadata["file_size"] + 16:
        raise ValueError("Encrypted file size does not match its metadata.")

    return metadata, metadata_end


def get_bundle_suggested_filename(input_path):
    """
    Read just the metadata from an encrypted bundle and return the embedded
    filename (sanitized). This helps the GUI suggest a save filename for
    decryption without fully parsing the bundle.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError("Encrypted file not found: " + str(input_path))

    with open(input_path, "rb") as file_obj:
        data = file_obj.read()

    metadata, _ = _read_bundle_metadata(data)
    return _sanitize_filename(metadata.get("filename", "decrypted_file"))


# ---------------------------------------------------------------------------
# 5. Complete File Encryption & Decryption
# ---------------------------------------------------------------------------

def encrypt_file(
    input_path,
    output_path,
    recipient_public_key_pem,
    overwrite=False
):
    """
    Encrypt a file for offline sharing:
    1. Read plaintext file and calculate its SHA-256 hash.
    2. Generate a random 32-byte AES key.
    3. Encrypt the file with AES-256-GCM (authenticated encryption).
    4. Encrypt the AES key with the recipient's RSA public key (OAEP + SHA-256).
    5. Write the self-contained encrypted bundle to output_path.
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

    # Step 2: Generate random AES session key
    aes_key = generate_aes_key()

    # Step 3: Encrypt AES key with recipient's RSA public key
    encrypted_key = encrypt_rsa(recipient_public_key_pem, aes_key)

    # Step 5: Build JSON metadata header
    original_filename = os.path.basename(input_path)
    metadata = {
        "format_version": 2,
        "filename": original_filename,
        "file_size": len(plaintext_bytes),
        "sha256": original_sha256,
        "encrypted_key": encrypted_key.hex()
    }
    metadata_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    header_len_bytes = struct.pack(">I", len(metadata_bytes))

    # Authenticate metadata as GCM additional data so filename, checksum,
    # wrapped key, and size cannot be changed independently of ciphertext.
    nonce, ciphertext_and_tag = encrypt_aes_gcm(plaintext_bytes, aes_key, metadata_bytes)

    # Step 6: Combine everything into the encrypted file bundle
    bundle = (
        FILE_MAGIC +
        header_len_bytes +
        metadata_bytes +
        nonce +
        ciphertext_and_tag
    )

    _write_output_safely(output_path, bundle, overwrite)

    return {
        "filename": original_filename,
        "file_size": len(plaintext_bytes),
        "encrypted_size": len(bundle),
        "sha256": original_sha256,
        "output_path": output_path
    }


def decrypt_file(input_path, output_path, recipient_private_key_pem, overwrite=False):
    """
    Decrypt an encrypted file bundle:
    1. Parse file format signature and metadata header.
    2. Decrypt the AES key using recipient's RSA private key.
    3. Decrypt ciphertext using AES-256-GCM (authentication is implicit).
    4. Recalculate SHA-256 hash and verify it matches original metadata hash.
    5. Save restored file to output_path.

    On GCM auth failure or SHA-256 mismatch the output file is NOT written
    and a ValueError is raised with a clear message.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError("Encrypted file not found: " + str(input_path))

    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Output file cannot be the same as the input file.")

    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError("Output file already exists: " + str(output_path))

    with open(input_path, "rb") as file_obj:
        data = file_obj.read()

    # Step 1: Parse and validate the bundle header
    metadata, metadata_end = _read_bundle_metadata(data)

    try:
        encrypted_key_bytes = bytes.fromhex(metadata["encrypted_key"])
    except (ValueError, TypeError):
        raise ValueError("Corrupted key encoding inside encrypted file.")

    # Extract GCM nonce and ciphertext + tag
    nonce = data[metadata_end:metadata_end + GCM_NONCE_SIZE]
    ciphertext_and_tag = data[metadata_end + GCM_NONCE_SIZE:]

    # Step 2: Recover AES key using RSA private key
    aes_key = decrypt_rsa(recipient_private_key_pem, encrypted_key_bytes)
    if len(aes_key) != 32:
        raise ValueError("Decrypted AES key has invalid size.")

    # Step 3: Decrypt the file using AES-256-GCM (authentication checked here)
    metadata_bytes = data[len(FILE_MAGIC) + 4:metadata_end]
    plaintext_bytes = decrypt_aes_gcm(nonce, ciphertext_and_tag, aes_key, metadata_bytes)

    # Step 4: Verify SHA-256 hash matches the original hash stored in metadata
    actual_sha256 = compute_sha256(plaintext_bytes)
    expected_sha256 = metadata["sha256"]
    if actual_sha256 != expected_sha256:
        raise ValueError(
            "Security alert: SHA-256 integrity check failed! "
            "Decrypted file does not match original checksum."
        )

    # Step 5: Sanitize the embedded filename
    safe_filename = _sanitize_filename(metadata.get("filename", "decrypted_file"))

    # Step 6: Save restored plaintext file
    _write_output_safely(output_path, plaintext_bytes, overwrite)

    return {
        "filename": safe_filename,
        "file_size": len(plaintext_bytes),
        "sha256": actual_sha256,
        "output_path": output_path
    }


def _write_output_safely(output_path, data, overwrite):
    """Write through a temporary file, avoiding partial plaintext outputs."""
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".secureshare-", dir=output_dir)
    try:
        with os.fdopen(fd, "wb") as out_obj:
            out_obj.write(data)
            out_obj.flush()
            os.fsync(out_obj.fileno())
        if overwrite:
            os.replace(temp_path, output_path)
        else:
            # Hard-link creation is atomic and fails if the destination exists.
            os.link(temp_path, output_path)
            os.unlink(temp_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
