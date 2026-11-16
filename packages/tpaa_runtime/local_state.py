"""Per-issued-agent conversation storage; separate from MemAuth memory.

SQLite serializes concurrent turns on the same issued agent. Only completed
user/assistant pairs are committed, so a failed model request is not replayed.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


class LocalConversationState:
    def __init__(self, agent_dir: Path, *, application_id: str, did: str, owner: str):
        self.agent_dir = Path(agent_dir)
        self.path = self.agent_dir / "state" / "conversations.db"
        self.identity = (application_id, did, owner)

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("CREATE TABLE IF NOT EXISTS identity (application_id TEXT NOT NULL, did TEXT NOT NULL, owner TEXT NOT NULL)")
        rows = self.db.execute("SELECT application_id, did, owner FROM identity").fetchall()
        if not rows:
            self.db.execute("INSERT INTO identity VALUES (?, ?, ?)", self.identity)
        elif rows != [self.identity]:
            self.db.rollback()
            self.db.close()
            raise ValueError("本地会话归属与颁发身份不一致")
        self.db.execute("CREATE TABLE IF NOT EXISTS turns (turn_id INTEGER PRIMARY KEY, question TEXT NOT NULL, answer TEXT NOT NULL)")
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.db.commit()
            else:
                self.db.rollback()
        finally:
            self.db.close()

    def history(self) -> list[tuple[str, str]]:
        return list(self.db.execute("SELECT question, answer FROM turns ORDER BY turn_id"))

    def append(self, question: str, answer: str) -> None:
        self.db.execute("INSERT INTO turns (question, answer) VALUES (?, ?)", (question, answer))
