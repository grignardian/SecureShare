"""
db.py  –  SQLite database layer for SecureShare
---------------------------------------------------------------------------
Two tables:
  users          – username, hashed password, RSA public key
  transfers      – every encrypted file: who sent it, who gets it, the
                   encrypted AES key, SHA-256 hash of the original file,
                   and the name of the .enc blob stored in encrypted_vault/
---------------------------------------------------------------------------
Everything runs in the same process – no sockets needed.
"""

import os, sqlite3, uuid, threading

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE   = os.path.join(BASE, "secureshare.db")
VAULT_DIR = os.path.join(BASE, "encrypted_vault")
os.makedirs(VAULT_DIR, exist_ok=True)

_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB_FILE)
    c.row_factory = sqlite3.Row
    return c


def init():
    """Create tables if they don't already exist."""
    with _lock, _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                salt          TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                public_key    TEXT NOT NULL,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS transfers (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                sender          TEXT NOT NULL,
                recipient       TEXT NOT NULL,
                filename        TEXT NOT NULL,
                file_size       INTEGER NOT NULL,
                sha256_hash     TEXT NOT NULL,
                enc_key_hex     TEXT NOT NULL,
                vault_file      TEXT NOT NULL,
                status          TEXT DEFAULT 'PENDING',
                created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)


# ── users ────────────────────────────────────────────────────────────────────

def add_user(username, salt, pw_hash, public_key) -> bool:
    try:
        with _lock, _conn() as c:
            c.execute("INSERT INTO users (username,salt,password_hash,public_key) VALUES (?,?,?,?)",
                      (username, salt, pw_hash, public_key))
        return True
    except sqlite3.IntegrityError:
        return False

def get_user(username) -> dict | None:
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None

def all_users() -> list[str]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT username FROM users ORDER BY username").fetchall()
    return [r["username"] for r in rows]

def get_public_key(username) -> str | None:
    u = get_user(username)
    return u["public_key"] if u else None

def update_public_key(username, public_key):
    with _lock, _conn() as c:
        c.execute("UPDATE users SET public_key=? WHERE username=?", (public_key, username))


# ── file transfers ────────────────────────────────────────────────────────────

def store_file(sender, recipient, filename, plaintext_size, sha256_hash,
               enc_key_hex, ciphertext: bytes) -> int:
    """Write ciphertext to vault, record transfer in DB.  Returns transfer ID."""
    vault_file = uuid.uuid4().hex + ".enc"
    with open(os.path.join(VAULT_DIR, vault_file), "wb") as f:
        f.write(ciphertext)
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO transfers (sender,recipient,filename,file_size,sha256_hash,enc_key_hex,vault_file)"
            " VALUES (?,?,?,?,?,?,?)",
            (sender, recipient, filename, plaintext_size, sha256_hash, enc_key_hex, vault_file)
        )
        return cur.lastrowid

def get_inbox(recipient) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM transfers WHERE recipient=? AND status='PENDING' ORDER BY created_at DESC",
            (recipient,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_transfer(tid) -> dict | None:
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM transfers WHERE id=?", (tid,)).fetchone()
    if not row:
        return None
    rec = dict(row)
    path = os.path.join(VAULT_DIR, rec["vault_file"])
    with open(path, "rb") as f:
        rec["ciphertext"] = f.read()
    return rec

def mark_downloaded(tid):
    with _lock, _conn() as c:
        c.execute("UPDATE transfers SET status='DOWNLOADED' WHERE id=?", (tid,))

def get_history(username) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM transfers WHERE sender=? OR recipient=? ORDER BY created_at DESC",
            (username, username)
        ).fetchall()
    return [dict(r) for r in rows]
