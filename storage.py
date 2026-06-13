"""
storage.py — Thread-safe SQLite storage for users and chat history.

Replaces chat_history.json and users.json.
Uses bcrypt for password hashing (salted, work-factor 12).
Images are saved to disk in the 'images/' folder; only the filename is stored.
"""

import os
import sqlite3
import logging
import threading
import uuid
import datetime
import bcrypt

logger = logging.getLogger(__name__)

DB_PATH    = "lazy_chat.db"
IMAGES_DIR = "images"

_local = threading.local()   # per-thread SQLite connection


def _get_conn() -> sqlite3.Connection:
    """Return a per-thread SQLite connection (created lazily)."""
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")   # concurrent readers OK
    return _local.conn


def init_db():
    """Create tables if they don't exist. Call once at server startup."""
    os.makedirs(IMAGES_DIR, exist_ok=True)
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            sender    TEXT    NOT NULL,
            content   TEXT    NOT NULL,
            msg_type  TEXT    NOT NULL DEFAULT 'text',
            timestamp TEXT    NOT NULL
        );
    """)
    conn.commit()
    logger.info("Database initialised at %s", DB_PATH)


# ── User management ───────────────────────────────────────────────────

def user_exists(username: str) -> bool:
    row = _get_conn().execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row is not None


def register_user(username: str, password: str) -> bool:
    """Hash password with bcrypt and insert. Returns False if taken."""
    if user_exists(username):
        return False
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    _get_conn().execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, hashed.decode()),
    )
    _get_conn().commit()
    return True


def verify_user(username: str, password: str) -> bool:
    """Return True if username exists and password matches."""
    row = _get_conn().execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row:
        return False
    return bcrypt.checkpw(password.encode(), row["password_hash"].encode())


# ── Message history ───────────────────────────────────────────────────

def save_message(sender: str, content: str, msg_type: str = "text"):
    """Persist a text message."""
    ts = datetime.datetime.now().strftime("%H:%M")
    _get_conn().execute(
        "INSERT INTO messages (sender, content, msg_type, timestamp) VALUES (?, ?, ?, ?)",
        (sender, content, msg_type, ts),
    )
    _get_conn().commit()


def save_image_message(sender: str, img_bytes: bytes) -> str:
    """
    Write image bytes to disk, store the filename in the DB.
    Returns the generated filename.
    """
    filename = f"{uuid.uuid4().hex}.bin"
    path = os.path.join(IMAGES_DIR, filename)
    with open(path, "wb") as f:
        f.write(img_bytes)
    save_message(sender, filename, msg_type="image")
    return filename


def load_image_bytes(filename: str) -> bytes | None:
    """Read image bytes from disk by filename. Returns None if missing."""
    path = os.path.join(IMAGES_DIR, filename)
    if not os.path.exists(path):
        logger.warning("Image file not found: %s", path)
        return None
    with open(path, "rb") as f:
        return f.read()


def load_history() -> list[sqlite3.Row]:
    """Return all messages ordered by insertion (id)."""
    return _get_conn().execute(
        "SELECT sender, content, msg_type, timestamp FROM messages ORDER BY id"
    ).fetchall()


# ── Image validation ──────────────────────────────────────────────────

# Magic bytes for allowed image formats
_MAGIC = {
    b"\x89PNG": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF8": "gif",
}


def is_valid_image(data: bytes) -> bool:
    """Return True only if *data* starts with a known image magic header."""
    for magic in _MAGIC:
        if data[:len(magic)] == magic:
            return True
    return False
