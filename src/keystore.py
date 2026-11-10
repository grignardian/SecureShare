"""
keystore.py - Local Key Management for SecureShare
--------------------------------------------------
Handles RSA-2048 key pair generation, saving, loading, and a local contact
book for an offline file encryption/decryption desktop application.

Security rules:
- Private keys are stored ONLY on the user's local machine inside the keys/ folder.
- Private keys are encrypted on disk using password-based encryption (PKCS#8).
- Private key files use owner-only permissions (0600) where supported by the OS.
- Private keys must NEVER leave the local machine.
"""

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")

CONTACTS_FILE = "contacts.json"


def ensure_keys_dir(keys_dir=KEYS_DIR):
    """Create the local keys directory if it does not exist."""
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir, exist_ok=True)


def get_private_key_path(keys_dir=KEYS_DIR):
    """Return the path where the user's encrypted private key is stored."""
    return os.path.join(keys_dir, "my_private_key.pem")


def get_public_key_path(keys_dir=KEYS_DIR):
    """Return the path where the user's public key is stored."""
    return os.path.join(keys_dir, "my_public_key.pem")


def has_private_key(keys_dir=KEYS_DIR):
    """Check if the encrypted private key file exists locally."""
    path = get_private_key_path(keys_dir)
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


def save_private_key(private_key, passphrase, keys_dir=KEYS_DIR, overwrite=False):
    """
    Encrypt the private key using the user's passphrase and save it to disk.
    Applies owner-only file permissions (chmod 600) where supported.
    """
    if not passphrase:
        raise ValueError("Passphrase is required to protect the private key.")

    ensure_keys_dir(keys_dir)
    priv_path = get_private_key_path(keys_dir)

    if os.path.exists(priv_path) and not overwrite:
        raise FileExistsError("Private key already exists: " + priv_path)

    # Encrypt private key PEM using password-based PKCS#8 encryption
    encrypted_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        )
    )

    with open(priv_path, "wb") as file_obj:
        file_obj.write(encrypted_pem_bytes)

    # Restrict file access to owner read/write only on POSIX systems
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass

    return priv_path


def save_public_key(public_pem, keys_dir=KEYS_DIR, overwrite=False):
    """Save the user's RSA public key PEM string to disk."""
    ensure_keys_dir(keys_dir)
    pub_path = get_public_key_path(keys_dir)

    if os.path.exists(pub_path) and not overwrite:
        raise FileExistsError("Public key already exists: " + pub_path)

    with open(pub_path, "w", encoding="utf-8") as file_obj:
        file_obj.write(public_pem)

    return pub_path


def load_private_key(passphrase, keys_dir=KEYS_DIR):
    """
    Load the passphrase-protected private key from disk and unlock it in memory.
    Returns: the decrypted private key object (kept strictly in memory).
    """
    if not passphrase:
        raise ValueError("Passphrase is required to unlock your private key.")

    priv_path = get_private_key_path(keys_dir)
    if not os.path.exists(priv_path):
        raise FileNotFoundError("Private key file not found: " + priv_path)

    with open(priv_path, "rb") as file_obj:
        encrypted_pem_bytes = file_obj.read()

    try:
        private_key = serialization.load_pem_private_key(
            encrypted_pem_bytes,
            password=passphrase.encode("utf-8")
        )
    except Exception:
        raise ValueError("Incorrect passphrase: could not unlock your private key.")

    return private_key


def load_public_key(keys_dir=KEYS_DIR):
    """Read and return the user's public key PEM string from disk."""
    pub_path = get_public_key_path(keys_dir)
    if not os.path.exists(pub_path):
        raise FileNotFoundError("Public key file not found: " + pub_path)

    with open(pub_path, "r", encoding="utf-8") as file_obj:
        return file_obj.read()


def export_public_key(dest_path, keys_dir=KEYS_DIR):
    """Copy the user's public key file to a user-chosen location for sharing."""
    pub_path = get_public_key_path(keys_dir)
    if not os.path.exists(pub_path):
        raise FileNotFoundError("Public key file not found: " + pub_path)

    shutil.copy2(pub_path, dest_path)
    return dest_path


def compute_fingerprint(public_pem):
    """
    Compute a SHA-256 fingerprint of a public key.
    Returns a colon-separated hex string like "AB:CD:EF:12:...".
    """
    if isinstance(public_pem, str):
        public_pem = public_pem.encode("utf-8")

    # Parse the PEM to get a validated public key object
    pub_key = serialization.load_pem_public_key(public_pem)

    # Encode as DER for a canonical byte representation
    der_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


# ---------------------------------------------------------------------------
# Contact book – a local JSON file for imported public keys
# ---------------------------------------------------------------------------

def _contacts_path(keys_dir=KEYS_DIR):
    """Return the full path to the contacts JSON file."""
    return os.path.join(keys_dir, CONTACTS_FILE)


def load_contacts(keys_dir=KEYS_DIR):
    """
    Load the contact book from disk.
    Returns a list of dicts, each with keys:
        {"name": str, "public_key": str, "fingerprint": str, "added": iso_timestamp}
    Returns an empty list if the file does not exist.
    """
    path = _contacts_path(keys_dir)
    if not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


def save_contacts(contacts, keys_dir=KEYS_DIR):
    """Write the contact list to the contacts JSON file on disk."""
    ensure_keys_dir(keys_dir)
    path = _contacts_path(keys_dir)

    with open(path, "w", encoding="utf-8") as file_obj:
        json.dump(contacts, file_obj, indent=2)


def add_contact(name, public_pem, keys_dir=KEYS_DIR):
    """
    Add a new contact to the local contact book.
    Validates that the PEM is a valid RSA public key, computes its fingerprint,
    and checks for duplicates by fingerprint and by name.
    Returns the newly created contact dict.
    """
    if isinstance(public_pem, bytes):
        public_pem = public_pem.decode("utf-8")

    # Validate that the PEM is a valid RSA public key
    try:
        pem_bytes = public_pem.encode("utf-8")
        pub_key = serialization.load_pem_public_key(pem_bytes)
    except Exception:
        raise ValueError("The provided PEM is not a valid public key.")

    # Ensure the key is RSA
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("The provided key is not an RSA public key.")

    fingerprint = compute_fingerprint(public_pem)
    contacts = load_contacts(keys_dir)

    # Check for duplicate fingerprint
    for contact in contacts:
        if contact["fingerprint"] == fingerprint:
            raise ValueError(
                "A contact with this key fingerprint already exists: "
                + contact["name"]
            )

    # Check for duplicate name
    for contact in contacts:
        if contact["name"] == name:
            raise ValueError("A contact named '" + name + "' already exists.")

    new_contact = {
        "name": name,
        "public_key": public_pem,
        "fingerprint": fingerprint,
        "added": datetime.now(timezone.utc).isoformat(),
    }

    contacts.append(new_contact)
    save_contacts(contacts, keys_dir)
    return new_contact


def remove_contact(name, keys_dir=KEYS_DIR):
    """Remove a contact from the contact book by name."""
    contacts = load_contacts(keys_dir)
    updated = [c for c in contacts if c["name"] != name]

    if len(updated) == len(contacts):
        raise ValueError("No contact found with name: " + name)

    save_contacts(updated, keys_dir)


def get_contact(name, keys_dir=KEYS_DIR):
    """
    Look up a contact by name.
    Returns the contact dict, or None if not found.
    """
    contacts = load_contacts(keys_dir)
    for contact in contacts:
        if contact["name"] == name:
            return contact
    return None


def import_contact_from_file(name, key_file_path, keys_dir=KEYS_DIR):
    """
    Import a contact's public key from a PEM file on disk.
    Reads the file, then delegates to add_contact for validation and storage.
    Returns the newly created contact dict.
    """
    if not os.path.isfile(key_file_path):
        raise FileNotFoundError("Key file not found: " + key_file_path)

    with open(key_file_path, "r", encoding="utf-8") as file_obj:
        public_pem = file_obj.read()

    return add_contact(name, public_pem, keys_dir)
