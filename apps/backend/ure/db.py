"""Persistência em SQLite (biblioteca padrão). Uma conexão protegida por lock."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  filename TEXT NOT NULL, kind TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
  status TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, artifact_id TEXT NOT NULL, kind TEXT NOT NULL,
  status TEXT NOT NULL, progress REAL NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '',
  error TEXT, params TEXT NOT NULL DEFAULT '{}', result TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_cache(
  key TEXT PRIMARY KEY, model TEXT NOT NULL, response TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_usage(day TEXT PRIMARY KEY, calls INTEGER NOT NULL DEFAULT 0);
"""
JSON_FIELDS = ("details", "result", "params")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    def _run(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = [self._decode(dict(r)) for r in cur.fetchall()]
            self._conn.commit()
            return rows

    @staticmethod
    def _decode(row: dict[str, Any]) -> dict[str, Any]:
        for key in JSON_FIELDS:
            if key in row and isinstance(row[key], str):
                row[key] = json.loads(row[key])
        return row

    def _one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self._run(sql, params)
        return rows[0] if rows else None

    # projetos
    def create_project(self, pid: str, name: str, description: str) -> dict[str, Any]:
        now = utcnow()
        self._run(
            "INSERT INTO projects(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)",
            (pid, name, description, now, now),
        )
        return self.get_project(pid)  # type: ignore[return-value]

    def get_project(self, pid: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM projects WHERE id=?", (pid,))

    def list_projects(self) -> list[dict[str, Any]]:
        return self._run("SELECT * FROM projects ORDER BY created_at DESC")

    def delete_project(self, pid: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM projects WHERE id=?", (pid,))
            self._conn.commit()
            return cur.rowcount > 0

    # artefatos
    def add_artifact(self, row: dict[str, Any]) -> dict[str, Any]:
        row = {**row, "details": json.dumps(row.get("details", {}), ensure_ascii=False)}
        cols = ",".join(row)
        marks = ",".join("?" for _ in row)
        self._run(f"INSERT INTO artifacts({cols}) VALUES({marks})", tuple(row.values()))
        return self.get_artifact(row["project_id"], row["id"])  # type: ignore[return-value]

    def get_artifact(self, pid: str, aid: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM artifacts WHERE project_id=? AND id=?", (pid, aid))

    def list_artifacts(self, pid: str) -> list[dict[str, Any]]:
        return self._run("SELECT * FROM artifacts WHERE project_id=? ORDER BY created_at DESC", (pid,))

    def update_artifact(self, aid: str, *, status: str | None = None, details: dict[str, Any] | None = None) -> None:
        sets, params = [], []
        if status is not None:
            sets.append("status=?")
            params.append(status)
        if details is not None:
            sets.append("details=?")
            params.append(json.dumps(details, ensure_ascii=False))
        if sets:
            self._run(f"UPDATE artifacts SET {','.join(sets)} WHERE id=?", (*params, aid))

    # jobs
    def create_job(self, row: dict[str, Any]) -> dict[str, Any]:
        now = utcnow()
        row = {
            **row,
            "created_at": now,
            "updated_at": now,
            "result": "{}",
            "params": json.dumps(row.get("params", {}), ensure_ascii=False),
        }
        cols = ",".join(row)
        marks = ",".join("?" for _ in row)
        self._run(f"INSERT INTO jobs({cols}) VALUES({marks})", tuple(row.values()))
        return self.get_job(row["id"])  # type: ignore[return-value]

    def update_job(self, jid: str, **fields: Any) -> None:
        if "result" in fields:
            fields["result"] = json.dumps(fields["result"], ensure_ascii=False)
        fields["updated_at"] = utcnow()
        sets = ",".join(f"{k}=?" for k in fields)
        self._run(f"UPDATE jobs SET {sets} WHERE id=?", (*fields.values(), jid))

    def get_job(self, jid: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM jobs WHERE id=?", (jid,))

    def recover_interrupted_jobs(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE jobs SET status='interrupted', error='interrompido pelo encerramento do servidor', "
                "updated_at=? WHERE status IN ('queued','running')",
                (utcnow(),),
            )
            self._conn.commit()
            return cur.rowcount

    # cache e orçamento de IA
    def cache_get(self, key: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM ai_cache WHERE key=?", (key,))

    def cache_put(self, key: str, model: str, response: str) -> None:
        self._run(
            "INSERT OR REPLACE INTO ai_cache(key,model,response,created_at) VALUES(?,?,?,?)",
            (key, model, response, utcnow()),
        )

    def ai_calls_today(self, day: str) -> int:
        row = self._one("SELECT calls FROM ai_usage WHERE day=?", (day,))
        return int(row["calls"]) if row else 0

    def ai_increment(self, day: str) -> None:
        self._run(
            "INSERT INTO ai_usage(day,calls) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET calls=calls+1",
            (day,),
        )
