"""Per-user note storage on SQLite."""

from __future__ import annotations

import sqlite3
import threading
import time

from pydantic import BaseModel

MAX_LIMIT = 50

SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner      TEXT NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS notes_owner ON notes (owner, created_at);
"""


class Note(BaseModel):
    id: int
    title: str
    body: str
    created_at: float


class NoteStore:
    """Every method takes the owner; there is no unscoped read path."""

    def __init__(self, path: str = ":memory:"):
        # One connection shared across threads, serialized by the lock.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)

    def create(self, owner: str, title: str, body: str) -> Note:
        now = time.time()
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO notes (owner, title, body, created_at) VALUES (?, ?, ?, ?)",
                (owner, title, body, now),
            )
        return Note(id=cur.lastrowid, title=title, body=body, created_at=now)

    def get(self, owner: str, note_id: int) -> Note | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, title, body, created_at FROM notes WHERE owner = ? AND id = ?",
                (owner, note_id),
            ).fetchone()
        return Note(**row) if row else None

    def search(self, owner: str, query: str, limit: int = 10) -> list[Note]:
        """Case-insensitive substring match on title or body, newest first."""
        limit = max(1, min(limit, MAX_LIMIT))
        # instr, not LIKE, so % and _ in the query match literally.
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, title, body, created_at FROM notes"
                " WHERE owner = ? AND instr(lower(title || ' ' || body), lower(?)) > 0"
                " ORDER BY created_at DESC, id DESC LIMIT ?",
                (owner, query, limit),
            ).fetchall()
        return [Note(**row) for row in rows]
