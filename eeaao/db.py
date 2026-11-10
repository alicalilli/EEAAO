"""SQLite storage. One file, data/eeaao.db, holds everything the app remembers."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "eeaao.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    url                TEXT NOT NULL DEFAULT '',
    in_scope           TEXT NOT NULL DEFAULT '',
    out_of_scope       TEXT NOT NULL DEFAULT '',
    rate_limit         REAL NOT NULL DEFAULT 5,
    headers            TEXT NOT NULL DEFAULT '{}',
    automation_allowed INTEGER NOT NULL DEFAULT 0,
    notes              TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

-- One press of "Run" on a department.
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id  INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    department  TEXT NOT NULL,
    bots        TEXT NOT NULL DEFAULT '[]',
    options     TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL,           -- running | done | stopped | failed | interrupted
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    summary     TEXT NOT NULL DEFAULT '{}'
);

-- Progress lines shown live on the dashboard.
CREATE TABLE IF NOT EXISTS run_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    at      TEXT NOT NULL,
    bot     TEXT NOT NULL DEFAULT '',
    level   TEXT NOT NULL DEFAULT 'info', -- info | warn | error
    message TEXT NOT NULL
);

-- Every request any bot makes: to targets, to passive sources, and DNS.
CREATE TABLE IF NOT EXISTS requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id  INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    run_id      INTEGER,
    bot         TEXT NOT NULL,
    at          TEXT NOT NULL,
    kind        TEXT NOT NULL,            -- target | source | dns
    method      TEXT NOT NULL,
    url         TEXT NOT NULL,
    status      INTEGER,
    duration_ms INTEGER,
    bytes       INTEGER,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS requests_program ON requests(program_id, id);

-- Inventory: hosts, URLs, parameters, JS files, DNS records, buckets...
CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    data       TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE (program_id, kind, value)
);

-- Responses bots already fetched, so later departments can analyse them
-- without asking the target again.
CREATE TABLE IF NOT EXISTS responses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id   INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    final_url    TEXT NOT NULL,
    status       INTEGER NOT NULL,
    headers      TEXT NOT NULL,            -- JSON list of [name, value]
    content_type TEXT NOT NULL DEFAULT '',
    body         BLOB,
    truncated    INTEGER NOT NULL DEFAULT 0,
    bot          TEXT NOT NULL,
    fetched_at   TEXT NOT NULL,
    UNIQUE (program_id, url)
);

-- Finding cards and leads, deduplicated by dedup_key.
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,              -- finding | lead
    type       TEXT NOT NULL,
    department TEXT NOT NULL,
    bot        TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'info',
    title      TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    evidence   TEXT NOT NULL DEFAULT '{}',
    dedup_key  TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'new', -- new | reviewed | dismissed | stale
    hits       INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE (program_id, dedup_key)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

FIELDS = ("name", "url", "in_scope", "out_of_scope", "rate_limit",
          "headers", "automation_allowed", "notes", "excluded_types")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init() -> None:
    with connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(programs)")}
        if "excluded_types" not in columns:  # added in v1
            conn.execute("ALTER TABLE programs ADD COLUMN excluded_types "
                         "TEXT NOT NULL DEFAULT '[]'")
        # A run cannot survive an app restart.
        conn.execute("UPDATE runs SET status = 'interrupted', finished_at = ? "
                     "WHERE status = 'running'", (now(),))


# ---------- programs ----------

def _row(row: sqlite3.Row) -> dict:
    program = dict(row)
    program["headers"] = json.loads(program["headers"])
    program["automation_allowed"] = bool(program["automation_allowed"])
    program["excluded_types"] = json.loads(program.get("excluded_types") or "[]")
    return program


def _values(data: dict) -> list:
    stored = dict(data, headers=json.dumps(data["headers"]),
                  automation_allowed=int(data["automation_allowed"]),
                  excluded_types=json.dumps(sorted(set(data.get("excluded_types", [])))))
    return [stored[field] for field in FIELDS]


def list_programs() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM programs ORDER BY name COLLATE NOCASE")
        return [_row(row) for row in rows]


def get_program(program_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM programs WHERE id = ?", (program_id,)).fetchone()
        return _row(row) if row else None


def create_program(data: dict) -> int:
    stamp = now()
    with connect() as conn:
        cursor = conn.execute(
            f"INSERT INTO programs ({', '.join(FIELDS)}, created_at, updated_at) "
            f"VALUES ({', '.join('?' * len(FIELDS))}, ?, ?)",
            _values(data) + [stamp, stamp])
        return cursor.lastrowid


def update_program(program_id: int, data: dict) -> bool:
    with connect() as conn:
        cursor = conn.execute(
            f"UPDATE programs SET {', '.join(f'{f} = ?' for f in FIELDS)}, "
            "updated_at = ? WHERE id = ?",
            _values(data) + [now(), program_id])
        return cursor.rowcount > 0


def delete_program(program_id: int) -> bool:
    with connect() as conn:
        return conn.execute("DELETE FROM programs WHERE id = ?",
                            (program_id,)).rowcount > 0


# ---------- runs ----------

def create_run(program_id: int, department: str, bots: list[str], options: dict) -> int:
    with connect() as conn:
        return conn.execute(
            "INSERT INTO runs (program_id, department, bots, options, status, started_at) "
            "VALUES (?, ?, ?, ?, 'running', ?)",
            (program_id, department, json.dumps(bots), json.dumps(options), now())).lastrowid


def finish_run(run_id: int, status: str, summary: dict) -> None:
    with connect() as conn:
        conn.execute("UPDATE runs SET status = ?, finished_at = ?, summary = ? WHERE id = ?",
                     (status, now(), json.dumps(summary), run_id))


def _run_row(row) -> dict:
    run = dict(row)
    for key in ("bots", "options", "summary"):
        run[key] = json.loads(run[key])
    return run


def get_run(run_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return _run_row(row) if row else None


def list_runs(program_id: int, limit: int = 20) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM runs WHERE program_id = ? ORDER BY id DESC LIMIT ?",
                            (program_id, limit))
        return [_run_row(row) for row in rows]


def add_event(run_id: int, bot: str, message: str, level: str = "info") -> None:
    with connect() as conn:
        conn.execute("INSERT INTO run_events (run_id, at, bot, level, message) "
                     "VALUES (?, ?, ?, ?, ?)", (run_id, now(), bot, level, message))


def list_events(run_id: int, after: int = 0) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM run_events WHERE run_id = ? AND id > ? "
                            "ORDER BY id LIMIT 1000", (run_id, after))
        return [dict(row) for row in rows]


# ---------- request log ----------

def log_request(program_id: int, run_id: int | None, bot: str, kind: str, method: str,
                url: str, status: int | None, duration_ms: int | None,
                size: int | None, error: str | None) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO requests (program_id, run_id, bot, at, kind, method, url, status, "
            "duration_ms, bytes, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (program_id, run_id, bot, now(), kind, method, url[:4000], status,
             duration_ms, size, error and error[:500]))


def list_requests(program_id: int, limit: int, offset: int, run_id: int | None = None):
    where, args = "program_id = ?", [program_id]
    if run_id:
        where += " AND run_id = ?"
        args.append(run_id)
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", args).fetchone()[0]
        rows = conn.execute(f"SELECT * FROM requests WHERE {where} ORDER BY id DESC "
                            "LIMIT ? OFFSET ?", args + [limit, offset])
        return total, [dict(row) for row in rows]


# ---------- assets ----------

def upsert_assets(program_id: int, items: list[tuple[str, str, dict]]) -> int:
    """items: (kind, value, data). Data is merged into what is stored with
    JSON merge-patch, so record lists that should accumulate as objects
    ({"sources": {"crtsh": 1}}). Returns how many rows were new."""
    if not items:
        return 0
    stamp = now()
    with connect() as conn:
        before = conn.total_changes
        conn.executemany(
            "INSERT INTO assets (program_id, kind, value, data, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (program_id, kind, value) DO NOTHING",
            [(program_id, k, v, json.dumps(d), stamp, stamp) for k, v, d in items])
        created = conn.total_changes - before
        conn.executemany(
            "UPDATE assets SET data = json_patch(data, ?), last_seen = ? "
            "WHERE program_id = ? AND kind = ? AND value = ?",
            [(json.dumps(d), stamp, program_id, k, v) for k, v, d in items if d])
        return created


def get_assets(program_id: int, kind: str, limit: int = 100_000) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM assets WHERE program_id = ? AND kind = ? "
                            "ORDER BY value LIMIT ?", (program_id, kind, limit))
        return [dict(row, data=json.loads(row["data"])) for row in rows]


def search_assets(program_id: int, kind: str | None, query: str, limit: int, offset: int):
    where, args = "program_id = ?", [program_id]
    if kind:
        where += " AND kind = ?"
        args.append(kind)
    if query:
        where += " AND value LIKE ? ESCAPE '\\'"
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        args.append(f"%{escaped}%")
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM assets WHERE {where}", args).fetchone()[0]
        rows = conn.execute(f"SELECT * FROM assets WHERE {where} ORDER BY kind, value "
                            "LIMIT ? OFFSET ?", args + [limit, offset])
        return total, [dict(row, data=json.loads(row["data"])) for row in rows]


def asset_counts(program_id: int) -> dict[str, int]:
    with connect() as conn:
        rows = conn.execute("SELECT kind, COUNT(*) AS n FROM assets WHERE program_id = ? "
                            "GROUP BY kind", (program_id,))
        return {row["kind"]: row["n"] for row in rows}


# ---------- stored responses ----------

def save_response(program_id: int, bot: str, url: str, final_url: str, status: int,
                  headers: list[tuple[str, str]], content_type: str, body: bytes,
                  truncated: bool) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO responses (program_id, url, final_url, status, headers, "
            "content_type, body, truncated, bot, fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT (program_id, url) DO UPDATE SET final_url = excluded.final_url, "
            "status = excluded.status, headers = excluded.headers, "
            "content_type = excluded.content_type, body = excluded.body, "
            "truncated = excluded.truncated, bot = excluded.bot, "
            "fetched_at = excluded.fetched_at",
            (program_id, url, final_url, status, json.dumps(headers), content_type,
             body, int(truncated), bot, now()))


def iter_responses(program_id: int, content_like: tuple[str, ...] = ()):
    """Yield stored responses one at a time (bodies can be large)."""
    where, args = "program_id = ?", [program_id]
    if content_like:
        where += " AND (" + " OR ".join("content_type LIKE ?" for _ in content_like) + ")"
        args += [f"%{c}%" for c in content_like]
    with connect() as conn:
        ids = [row[0] for row in conn.execute(f"SELECT id FROM responses WHERE {where}", args)]
    for response_id in ids:
        with connect() as conn:
            row = conn.execute("SELECT * FROM responses WHERE id = ?", (response_id,)).fetchone()
        if row:
            yield dict(row, headers=json.loads(row["headers"]))


def get_response(program_id: int, url: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM responses WHERE program_id = ? AND url = ?",
                           (program_id, url)).fetchone()
        return dict(row, headers=json.loads(row["headers"])) if row else None


# ---------- findings and leads ----------

def dedup_key(type_: str, key: str) -> str:
    return hashlib.sha256(f"{type_}\x00{key}".encode()).hexdigest()[:32]


def upsert_finding(program_id: int, item: dict) -> bool:
    """Insert a finding/lead, or bump hits/last_seen of the existing card.
    Returns True when it is new."""
    stamp = now()
    key = dedup_key(item["type"], item["key"])
    with connect() as conn:
        cursor = conn.execute(
            "INSERT INTO findings (program_id, kind, type, department, bot, severity, title, "
            "target, detail, evidence, dedup_key, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (program_id, dedup_key) DO NOTHING",
            (program_id, item["kind"], item["type"], item["department"], item["bot"],
             item["severity"], item["title"][:300], item["target"][:2000],
             item["detail"][:5000], json.dumps(item["evidence"]), key, stamp, stamp))
        if cursor.rowcount:
            return True
        # Seen again: refresh the card with the bot's current wording, and bring
        # it back if it had been retired as "no longer seen".
        conn.execute("UPDATE findings SET hits = hits + 1, last_seen = ?, evidence = ?, "
                     "severity = ?, title = ?, target = ?, detail = ?, "
                     "status = CASE WHEN status = 'stale' THEN 'new' ELSE status END "
                     "WHERE program_id = ? AND dedup_key = ?",
                     (stamp, json.dumps(item["evidence"]), item["severity"],
                      item["title"][:300], item["target"][:2000], item["detail"][:5000],
                      program_id, key))
        return False


def retire_unseen(program_id: int, bot: str, since: str) -> int:
    """Mark a bot's untouched 'new' cards as no longer seen ('stale'). Cards
    you reviewed or dismissed are yours and are left alone."""
    with connect() as conn:
        return conn.execute(
            "UPDATE findings SET status = 'stale' WHERE program_id = ? AND bot = ? "
            "AND status = 'new' AND last_seen < ?", (program_id, bot, since)).rowcount


def list_findings(program_id: int, kind: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE program_id = ? AND kind = ? ORDER BY "
            "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, "
            "last_seen DESC", (program_id, kind))
        return [dict(row, evidence=json.loads(row["evidence"])) for row in rows]


def set_finding_status(finding_id: int, status: str) -> bool:
    with connect() as conn:
        return conn.execute("UPDATE findings SET status = ? WHERE id = ?",
                            (status, finding_id)).rowcount > 0


def finding_program(finding_id: int) -> int | None:
    with connect() as conn:
        row = conn.execute("SELECT program_id FROM findings WHERE id = ?",
                           (finding_id,)).fetchone()
        return row[0] if row else None


# ---------- settings ----------

def get_setting(key: str) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None


def set_setting(key: str, value: str | None) -> None:
    with connect() as conn:
        if value is None:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        else:
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                         "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))
