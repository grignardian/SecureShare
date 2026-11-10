"""
keystore.py - Local Key Management for SecureShare
--------------------------------------------------
Handles RSA-2048 key pair generation, saving, and loading on the client machine.
Security rules:
- Private keys are stored ONLY on the user's local machine inside the keys/ folder.
- Private keys are encrypted on disk using password-based encryption (PKCS#8).
- Private key files use owner-only permissions (0600) where supported by the OS.
- Private keys must NEVER be sent to the server or committed to Git.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")


def ensure_keys_dir(keys_dir=KEYS_DIR):
    """Create the local keys directory if it does not exist."""
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir, exist_ok=True)


def get_private_key_path(username, keys_dir=KEYS_DIR):
    """Return the path where a user's encrypted private key is stored."""
    clean_name = os.path.basename(username)
    return os.path.join(keys_dir, clean_name + "_private.pem")


def get_public_key_path(username, keys_dir=KEYS_DIR):
    """Return the path where a user's public key is stored."""
    clean_name = os.path.basename(username)
    return os.path.join(keys_dir, clean_name + "_public.pem")


def has_private_key(username, keys_dir=KEYS_DIR):
    """Check if the encrypted private key file exists locally for this user."""
    path = get_private_key_path(username, keys_dir)
    return os.path.isfile(path)


def generate_rsa_keypair():
    """
    Generate a fresh 2048-bit RSA key pair.
    Returns: (private_key_object, public_key_pem_string)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_key, public_pem


def save_private_key(username, private_key, password, keys_dir=KEYS_DIR, overwrite=False):
    """
    Encrypt the private key using the user's password and save it to disk.
    Applies owner-only file permissions (chmod 600) where supported.
    """
    if not password:
        raise ValueError("Password is required to protect the private key.")

    ensure_keys_dir(keys_dir)
    priv_path = get_private_key_path(username, keys_dir)

    if os.path.exists(priv_path) and not overwrite:
        raise FileExistsError("Private key already exists for user: " + username)

    # Encrypt private key PEM using password-based PKCS#8 encryption
    encrypted_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
    )

    with open(priv_path, "wb") as file_obj:
        file_obj.write(encrypted_pem_bytes)

    # Restrict file access to owner read/write only on POSIX systems
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass

    return priv_path


def save_public_key(username, public_pem, keys_dir=KEYS_DIR, overwrite=False):
    """Save a user's RSA public key PEM string to disk."""
    ensure_keys_dir(keys_dir)
    pub_path = get_public_key_path(username, keys_dir)

    if os.path.exists(pub_path) and not overwrite:
        raise FileExistsError("Public key already exists for user: " + username)

    with open(pub_path, "w", encoding="utf-8") as file_obj:
        file_obj.write(public_pem)

    return pub_path


def load_public_key(username, keys_dir=KEYS_DIR):
    """Read and return a user's public key PEM string from disk."""
    pub_path = get_public_key_path(username, keys_dir)
    if not os.path.exists(pub_path):
        raise FileNotFoundError("Public key file not found: " + pub_path)

    with open(pub_path, "r", encoding="utf-8") as file_obj:
        return file_obj.read()


def load_private_key(username, password, keys_dir=KEYS_DIR):
    """
    Load the password-protected private key from disk and unlock it in memory.
    Returns: unencrypted private key PEM string (kept strictly in memory).
    """
    if not password:
        raise ValueError("Password is required to unlock your private key.")

    priv_path = get_private_key_path(username, keys_dir)
    if not os.path.exists(priv_path):
        raise FileNotFoundError(
            "Local private key not found for '" + username + "'. "
            "If you registered on another computer, please import your encrypted private key."
        )

    with open(priv_path, "rb") as file_obj:
        encrypted_pem_bytes = file_obj.read()

    try:
        private_key = serialization.load_pem_private_key(
            encrypted_pem_bytes,
            password=password.encode("utf-8")
        )
    except Exception:
        raise ValueError("Incorrect password: could not unlock your private key.")

    # Return unlocked PEM in memory so crypto functions can unwrap session keys
    unlocked_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    return unlocked_pem


def create_and_save_user_keys(username, password, keys_dir=KEYS_DIR, overwrite=False):
    """
    Convenience function for registration:
    Generates an RSA-2048 key pair, saves encrypted private key and public key locally,
    and returns the public key PEM string to be uploaded to the server.
    """
    private_key, public_pem = generate_rsa_keypair()
    save_private_key(username, private_key, password, keys_dir=keys_dir, overwrite=overwrite)
    save_public_key(username, public_pem, keys_dir=keys_dir, overwrite=overwrite)
    return public_pem


def import_private_key(username, source_path, password, keys_dir=KEYS_DIR, overwrite=False):
    """
    Import an existing encrypted private key file (for logging in on a new computer).
    Verifies the password can unlock the key before saving it locally.
    """
    if not os.path.isfile(source_path):
        raise FileNotFoundError("Selected key file not found: " + source_path)

    with open(source_path, "rb") as file_obj:
        key_bytes = file_obj.read()

    try:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=password.encode("utf-8")
        )
    except Exception:
        raise ValueError("Could not unlock imported key with the provided password.")

    priv_path = save_private_key(username, private_key, password, keys_dir=keys_dir, overwrite=overwrite)
    return priv_path
