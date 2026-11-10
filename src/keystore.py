"""
keystore.py - Key Management for SecureShare
--------------------------------------------
This module handles:
1. Generating RSA-2048 key pairs (public and private keys).
2. Saving keys as standard PEM files in the 'keys/' directory.
3. Loading public and private keys from disk.
4. Listing existing keys for the user interface.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Root directory of the project and the keys directory
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SRC_DIR)
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")


def ensure_keys_directory():
    """Make sure the keys folder exists."""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR, exist_ok=True)


def generate_keypair(key_name: str) -> tuple[str, str]:
    """
    Generate a 2048-bit RSA key pair and save them to keys/:
      - keys/{key_name}_private.pem
      - keys/{key_name}_public.pem
    Returns: (private_pem_str, public_pem_str)
    """
    ensure_keys_directory()

    # Generate RSA private key (2048-bit, exponent 65537)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Convert private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Convert public key to PEM format
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Save to disk
    priv_file = os.path.join(KEYS_DIR, f"{key_name}_private.pem")
    pub_file = os.path.join(KEYS_DIR, f"{key_name}_public.pem")

    with open(priv_file, "w", encoding="utf-8") as f:
        f.write(private_pem)

    with open(pub_file, "w", encoding="utf-8") as f:
        f.write(public_pem)

    return private_pem, public_pem


def load_public_key(name_or_path: str) -> str:
    """
    Load a public key PEM string by user name or by file path.
    Example: load_public_key("bob") or load_public_key("/path/to/bob_public.pem")
    """
    # Check if a direct file path was provided
    if os.path.isfile(name_or_path):
        with open(name_or_path, "r", encoding="utf-8") as f:
            return f.read()

    # Otherwise look up keys/{name_or_path}_public.pem
    key_file = os.path.join(KEYS_DIR, f"{name_or_path}_public.pem")
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Public key file not found: {key_file}")

    with open(key_file, "r", encoding="utf-8") as f:
        return f.read()


def load_private_key(name_or_path: str) -> str:
    """
    Load a private key PEM string by user name or by file path.
    Example: load_private_key("bob") or load_private_key("/path/to/bob_private.pem")
    """
    # Check if a direct file path was provided
    if os.path.isfile(name_or_path):
        with open(name_or_path, "r", encoding="utf-8") as f:
            return f.read()

    # Otherwise look up keys/{name_or_path}_private.pem
    key_file = os.path.join(KEYS_DIR, f"{name_or_path}_private.pem")
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Private key file not found: {key_file}")

    with open(key_file, "r", encoding="utf-8") as f:
        return f.read()


def list_available_keys() -> list[str]:
    """
    Return a list of available key names found in the keys/ directory.
    For example: ['alice', 'bob']
    """
    ensure_keys_directory()
    names = set()
    for fname in os.listdir(KEYS_DIR):
        if fname.endswith("_public.pem"):
            name = fname[:-11]  # Remove '_public.pem'
            names.add(name)
        elif fname.endswith("_private.pem"):
            name = fname[:-12]  # Remove '_private.pem'
            names.add(name)
    return sorted(list(names))


def ensure_default_keys():
    """
    Make sure default demo keys ('alice' and 'bob') exist.
    If not present, generates them automatically.
    """
    ensure_keys_directory()
    for name in ["alice", "bob"]:
        priv = os.path.join(KEYS_DIR, f"{name}_private.pem")
        pub = os.path.join(KEYS_DIR, f"{name}_public.pem")
        if not (os.path.exists(priv) and os.path.exists(pub)):
            generate_keypair(name)
