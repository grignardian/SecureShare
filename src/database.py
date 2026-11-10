"""
database.py - SQLite Database Operations for SecureShare Server
---------------------------------------------------------------
Manages two tables inside server_data/secureshare.db:
1. users: Stores registered usernames, PBKDF2 password hashes, salts, and RSA public keys.
2. files: Stores encrypted file transfer metadata (sender, receiver, filename, size, SHA-256).

Note: Plaintext passwords, private keys, and plaintext files are NEVER stored here.
"""

import os
import sqlite3


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
SERVER_DATA_DIR = os.path.join(PROJECT_ROOT, "server_data")
FILES_DIR = os.path.join(SERVER_DATA_DIR, "files")
DEFAULT_DB_PATH = os.path.join(SERVER_DATA_DIR, "secureshare.db")


def ensure_server_directories(files_dir=FILES_DIR):
    """Create server_data/ and server_data/files/ directories if they do not exist."""
    if not os.path.exists(SERVER_DATA_DIR):
        os.makedirs(SERVER_DATA_DIR, exist_ok=True)
    if not os.path.exists(files_dir):
        os.makedirs(files_dir, exist_ok=True)


def get_connection(db_path=DEFAULT_DB_PATH):
    """Open a connection to the SQLite database."""
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DEFAULT_DB_PATH):
    """Create the users and files tables if they do not already exist."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            public_key    TEXT NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            file_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sender            TEXT NOT NULL,
            receiver          TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename   TEXT NOT NULL,
            file_size         INTEGER NOT NULL,
            sha256            TEXT NOT NULL,
            uploaded_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# User Operations
# ---------------------------------------------------------------------------

def add_user(username, password_hash, salt, public_key, db_path=DEFAULT_DB_PATH):
    """
    Insert a new user record into SQLite.
    Returns True if created, False if the username already exists.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, public_key) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, public_key)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user(username, db_path=DEFAULT_DB_PATH):
    """Retrieve a user row as a dictionary, or None if not found."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None
    return dict(row)


def get_public_key(username, db_path=DEFAULT_DB_PATH):
    """Return a user's RSA public key PEM string, or None if not found."""
    user = get_user(username, db_path=db_path)
    if user is None:
        return None
    return user["public_key"]


def list_users(db_path=DEFAULT_DB_PATH):
    """Return a sorted list of all registered usernames."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users ORDER BY username ASC")
    rows = cursor.fetchall()
    conn.close()

    usernames = []
    for row in rows:
        usernames.append(row["username"])
    return usernames


# ---------------------------------------------------------------------------
# File Operations
# ---------------------------------------------------------------------------

def save_file_record(
    sender,
    receiver,
    original_filename,
    stored_filename,
    file_size,
    sha256,
    db_path=DEFAULT_DB_PATH
):
    """Save uploaded encrypted file metadata and return the generated file_id."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO files (sender, receiver, original_filename, stored_filename, file_size, sha256)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (sender, receiver, original_filename, stored_filename, file_size, sha256)
    )
    conn.commit()
    file_id = cursor.lastrowid
    conn.close()
    return file_id


def get_received_files(username, db_path=DEFAULT_DB_PATH):
    """Return a list of files sent to this specific user, newest first."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT file_id, sender, receiver, original_filename, file_size, sha256, uploaded_at
        FROM files
        WHERE receiver = ?
        ORDER BY file_id DESC
        """,
        (username,)
    )
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append(dict(row))
    return results


def get_file_history(username, db_path=DEFAULT_DB_PATH):
    """Return a list of all files either sent or received by this user, newest first."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT file_id, sender, receiver, original_filename, file_size, sha256, uploaded_at
        FROM files
        WHERE sender = ? OR receiver = ?
        ORDER BY file_id DESC
        """,
        (username, username)
    )
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append(dict(row))
    return results


def get_file_by_id(file_id, db_path=DEFAULT_DB_PATH):
    """Return a single file record (including stored_filename) by its file_id."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE file_id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None
    return dict(row)
