"""
auth.py - User Registration and Login Security for SecureShare
--------------------------------------------------------------
Uses PBKDF2-HMAC-SHA256 with a random 16-byte salt and 200,000 iterations
to securely hash passwords before storing them in SQLite.
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization

try:
    from . import database
except ImportError:
    import database


PBKDF2_ITERATIONS = 200_000


def is_valid_username(username):
    """Check that username is 2-32 chars and uses only letters, numbers, '_' or '-'."""
    if not isinstance(username, str):
        return False
    if len(username) < 2 or len(username) > 32:
        return False
    for char in username:
        if not (char.isalnum() or char in ("_", "-")):
            return False
    return True


def is_valid_public_key(public_key_pem):
    """Verify that the uploaded public key string is a valid PEM RSA public key."""
    try:
        serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        return True
    except Exception:
        return False


def hash_password(password):
    """
    Generate a random 16-byte salt and hash the password using PBKDF2-HMAC-SHA256.
    Returns: (salt_hex, password_hash_hex)
    """
    salt_bytes = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS
    )
    return salt_bytes.hex(), hash_bytes.hex()


def verify_password(password, salt_hex, expected_hash_hex):
    """Verify a password against the stored salt and PBKDF2 hash."""
    salt_bytes = bytes.fromhex(salt_hex)
    actual_hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(actual_hash_bytes.hex(), expected_hash_hex)


def register_user(username, password, public_key_pem, db_path=database.DEFAULT_DB_PATH):
    """
    Register a new user account in the database.
    Returns: (success_bool, message_string)
    """
    clean_username = username.strip().lower()

    if not is_valid_username(clean_username):
        return False, "Username must be 2 to 32 characters (letters, numbers, '_' or '-')."

    if not password or len(password) < 4:
        return False, "Password must be at least 4 characters long."

    if not is_valid_public_key(public_key_pem):
        return False, "Invalid RSA public key provided."

    # Hash password with fresh random salt
    salt_hex, hash_hex = hash_password(password)

    # Attempt to insert into SQLite
    created = database.add_user(
        username=clean_username,
        password_hash=hash_hex,
        salt=salt_hex,
        public_key=public_key_pem,
        db_path=db_path
    )

    if not created:
        return False, "Username '" + clean_username + "' is already registered."

    return True, "Account created successfully for '" + clean_username + "'."


def login_user(username, password, db_path=database.DEFAULT_DB_PATH):
    """
    Verify user login credentials against SQLite.
    Returns: (success_bool, message_string)
    """
    clean_username = username.strip().lower()
    if not clean_username or not password:
        return False, "Username and password are required."

    user = database.get_user(clean_username, db_path=db_path)
    if user is None:
        return False, "Invalid username or password."

    is_match = verify_password(password, user["salt"], user["password_hash"])
    if not is_match:
        return False, "Invalid username or password."

    return True, "Login successful."
