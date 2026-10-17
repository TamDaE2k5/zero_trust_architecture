"""Persistent, bounded session allowlist. Store only hashes of token identifiers."""

import hashlib
from contextlib import contextmanager
import sqlite3
import time
from pathlib import Path


class Sessions:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)"
            )

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=3)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def identifier(claims):
        return hashlib.sha256(claims["jti"].encode()).hexdigest()

    def add(self, claims):
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute("DELETE FROM sessions WHERE expires <= ?", (int(time.time()),))
            if database.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 10000:
                raise ValueError("Session capacity reached")
            database.execute(
                "INSERT INTO sessions VALUES (?, ?)", (self.identifier(claims), claims["exp"])
            )

    def active(self, claims):
        with self.connect() as database:
            row = database.execute(
                "SELECT expires FROM sessions WHERE id = ?", (self.identifier(claims),)
            ).fetchone()
            return bool(row and row[0] > time.time())

    def revoke(self, claims):
        with self.connect() as database:
            database.execute("DELETE FROM sessions WHERE id = ?", (self.identifier(claims),))
