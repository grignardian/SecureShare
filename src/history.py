"""Local SQLite history for successful file encryption and decryption actions."""
import os
import sqlite3
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "local_data")
DEFAULT_DB_PATH = os.path.join(DATA_DIR, "history.sqlite3")


def initialize(db_path=DEFAULT_DB_PATH):
    """Create the history database and table if they do not already exist."""
    parent = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(parent, exist_ok=True)
    with sqlite3.connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS file_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('Encrypt', 'Decrypt')),
                filename TEXT NOT NULL,
                source_path TEXT NOT NULL,
                output_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                recipient TEXT NOT NULL DEFAULT ''
            )
        """)


def record_event(action, filename, source_path, output_path, file_size,
                 recipient="", db_path=DEFAULT_DB_PATH):
    """Record a completed operation. No file contents or cryptographic keys are stored."""
    if action not in ("Encrypt", "Decrypt"):
        raise ValueError("History action must be Encrypt or Decrypt.")
    initialize(db_path)
    occurred_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """INSERT INTO file_history
               (occurred_at, action, filename, source_path, output_path, file_size, recipient)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (occurred_at, action, str(filename), os.path.abspath(source_path),
             os.path.abspath(output_path), int(file_size), str(recipient or ""))
        )
        return cursor.lastrowid


def list_events(db_path=DEFAULT_DB_PATH):
    """Return recent history rows, newest first."""
    initialize(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT id, occurred_at, action, filename, source_path, output_path,
                      file_size, recipient
               FROM file_history ORDER BY id DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def clear_history(db_path=DEFAULT_DB_PATH):
    """Delete all history entries while keeping the local database available."""
    initialize(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute("DELETE FROM file_history")
        # Reset the autoincrement counter for a clean local history view.
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'file_history'")
