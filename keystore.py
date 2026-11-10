"""
keystore.py  –  Keyring & Profile Manager for SecureShare
---------------------------------------------------------------------------
Replaces the local transfer database with cross-device key management:
  1. Fixed Cross-Device Profiles (`keys/` directory, tracked in Git):
       - `bob` and `alice` use fixed RSA-2048 key pairs + PBKDF2 credentials.
       - Any device running this project has identical keys for `bob` & `alice`,
         allowing real encryption on Device A -> WhatsApp/Email -> decryption on Device B.
  2. Local Profiles & Imported Contacts (`local_keys/` directory, gitignored):
       - Users can create custom accounts or import any external `.pem` public key.
"""

import os
import json
import crypto

BASE       = os.path.dirname(os.path.abspath(__file__))
FIXED_DIR  = os.path.join(BASE, "keys")
LOCAL_DIR  = os.path.join(BASE, "local_keys")
CONTACTS_DIR = os.path.join(LOCAL_DIR, "contacts")

FIXED_PROFILES_FILE = os.path.join(FIXED_DIR, "fixed_profiles.json")
LOCAL_PROFILES_FILE = os.path.join(LOCAL_DIR, "profiles.json")

FIXED_USERS = ("bob", "alice")

for d in (FIXED_DIR, LOCAL_DIR, CONTACTS_DIR):
    os.makedirs(d, exist_ok=True)


def _read_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_json(path: str, data: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _read_text(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _write_text(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def ensure_fixed_profiles():
    """
    Ensure fixed demo accounts (`bob`, `alice`) exist in `keys/`.
    In normal usage these files are already present in the repository so all
    devices share the exact same RSA-2048 key pairs.
    """
    defaults = [("bob", "Bob123!"), ("alice", "Alice123!")]
    profiles = _read_json(FIXED_PROFILES_FILE)
    changed = False

    for username, password in defaults:
        priv_path = os.path.join(FIXED_DIR, f"{username}_private.pem")
        pub_path  = os.path.join(FIXED_DIR, f"{username}_public.pem")
        if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
            priv_pem, pub_pem = crypto.generate_rsa_keypair()
            _write_text(priv_path, priv_pem)
            _write_text(pub_path, pub_pem)

        if username not in profiles:
            salt, pw_hash = crypto.hash_password(password)
            profiles[username] = {"salt": salt, "password_hash": pw_hash}
            changed = True

    if changed or not os.path.exists(FIXED_PROFILES_FILE):
        _write_json(FIXED_PROFILES_FILE, profiles)


def is_fixed_user(username: str) -> bool:
    return username in FIXED_USERS


def user_exists(username: str) -> bool:
    ensure_fixed_profiles()
    if username in _read_json(FIXED_PROFILES_FILE):
        return True
    return username in _read_json(LOCAL_PROFILES_FILE)


def authenticate(username: str, password: str) -> tuple[bool, str]:
    """Verify username and password via PBKDF2-HMAC-SHA256."""
    ensure_fixed_profiles()
    fixed = _read_json(FIXED_PROFILES_FILE)
    rec = fixed.get(username)
    if not rec:
        local = _read_json(LOCAL_PROFILES_FILE)
        rec = local.get(username)

    if not rec:
        return False, f"User '{username}' not found. Click 'Create Account'."

    if not crypto.check_password(password, rec["salt"], rec["password_hash"]):
        return False, "Invalid password. Please check your credentials."

    return True, "OK"


def register_user(username: str, password: str) -> tuple[bool, str]:
    """Create a local user profile with PBKDF2 password hash and fresh RSA-2048 keys."""
    username = username.strip()
    if not username:
        return False, "Please enter a username."
    if any(ch in username for ch in r'\/:*?"<>| '):
        return False, "Username cannot contain spaces or special path characters."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if user_exists(username):
        return False, f"Username '{username}' already exists."

    priv_pem, pub_pem = crypto.generate_rsa_keypair()
    _write_text(os.path.join(LOCAL_DIR, f"{username}_private.pem"), priv_pem)
    _write_text(os.path.join(LOCAL_DIR, f"{username}_public.pem"), pub_pem)

    salt, pw_hash = crypto.hash_password(password)
    local = _read_json(LOCAL_PROFILES_FILE)
    local[username] = {"salt": salt, "password_hash": pw_hash}
    _write_json(LOCAL_PROFILES_FILE, local)

    return True, f"Account '{username}' created with a new RSA-2048 keypair!"


def get_private_key(username: str) -> str | None:
    """Return RSA Private Key PEM for username."""
    ensure_fixed_profiles()
    if is_fixed_user(username):
        return _read_text(os.path.join(FIXED_DIR, f"{username}_private.pem"))
    return _read_text(os.path.join(LOCAL_DIR, f"{username}_private.pem"))


def get_public_key(name: str) -> str | None:
    """Look up a public key PEM by profile name or imported contact name."""
    ensure_fixed_profiles()
    # 1. Fixed profiles
    if is_fixed_user(name):
        return _read_text(os.path.join(FIXED_DIR, f"{name}_public.pem"))
    # 2. Local profiles
    local_pub = os.path.join(LOCAL_DIR, f"{name}_public.pem")
    if os.path.exists(local_pub):
        return _read_text(local_pub)
    # 3. Imported contacts
    contact_pub = os.path.join(CONTACTS_DIR, f"{name}.pem")
    if os.path.exists(contact_pub):
        return _read_text(contact_pub)
    return None


def list_all_recipients(exclude_user: str | None = None) -> list[dict]:
    """
    Return all known recipients with public keys:
    [{"name": ..., "kind": "Fixed Cross-Device" | "Local Profile" | "Imported Contact", "fingerprint": ...}]
    """
    ensure_fixed_profiles()
    seen = set()
    result = []

    def _add(name: str, kind: str, pem: str | None):
        if not pem or name == exclude_user or name in seen:
            return
        seen.add(name)
        result.append({
            "name": name,
            "kind": kind,
            "fingerprint": crypto.key_fingerprint(pem),
        })

    for u in FIXED_USERS:
        _add(u, "Fixed Cross-Device", get_public_key(u))

    for u in sorted(_read_json(LOCAL_PROFILES_FILE).keys()):
        _add(u, "Local Profile", get_public_key(u))

    if os.path.isdir(CONTACTS_DIR):
        for fname in sorted(os.listdir(CONTACTS_DIR)):
            if fname.endswith(".pem"):
                cname = fname[:-4]
                _add(cname, "Imported Contact", _read_text(os.path.join(CONTACTS_DIR, fname)))

    return result


def import_contact(name: str, pub_pem: str) -> tuple[bool, str]:
    """Validate and save an external recipient's RSA Public Key (.pem)."""
    name = name.strip()
    if not name:
        return False, "Please enter a contact name."
    if any(ch in name for ch in r'\/:*?"<>| '):
        return False, "Contact name cannot contain spaces or special path characters."
    if not crypto.validate_public_key(pub_pem):
        return False, "Invalid RSA Public Key PEM file."
    if is_fixed_user(name):
        return False, f"'{name}' is a built-in fixed profile and cannot be overwritten."

    _write_text(os.path.join(CONTACTS_DIR, f"{name}.pem"), pub_pem.strip() + "\n")
    fp = crypto.key_fingerprint(pub_pem)
    return True, f"Imported public key for '{name}' (Fingerprint: {fp})."


def delete_contact(name: str) -> bool:
    path = os.path.join(CONTACTS_DIR, f"{name}.pem")
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def regenerate_local_keypair(username: str) -> tuple[bool, str]:
    """Generate a new RSA-2048 keypair for a custom local user (not fixed profiles)."""
    if is_fixed_user(username):
        return False, (
            f"'{username}' uses a fixed cross-device keypair so Device A and Device B "
            f"can decrypt each other's files. Create a custom account to generate unique keys."
        )
    if not user_exists(username):
        return False, "User profile not found."

    priv_pem, pub_pem = crypto.generate_rsa_keypair()
    _write_text(os.path.join(LOCAL_DIR, f"{username}_private.pem"), priv_pem)
    _write_text(os.path.join(LOCAL_DIR, f"{username}_public.pem"), pub_pem)
    fp = crypto.key_fingerprint(pub_pem)
    return True, f"New RSA-2048 keypair generated! New Public Fingerprint: {fp}"
