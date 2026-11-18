"""
AegisX — database schema & migrations.

SQLite with WAL mode; a versioned, ordered migration list keeps upgrades
idempotent. Schema version is stored in PRAGMA user_version.
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 1

# Each migration: (version, "description", [sql statements])
MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (
        1,
        "initial schema",
        [
            """
            CREATE TABLE IF NOT EXISTS indicators (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                value         TEXT NOT NULL UNIQUE,
                type          TEXT NOT NULL,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                risk_score    INTEGER NOT NULL DEFAULT 0,
                severity      TEXT NOT NULL DEFAULT 'info',
                confidence    REAL NOT NULL DEFAULT 0,
                tags          TEXT NOT NULL DEFAULT '[]',
                description   TEXT DEFAULT '',
                country       TEXT DEFAULT '',
                asn           TEXT DEFAULT '',
                asn_name      TEXT DEFAULT '',
                status        TEXT NOT NULL DEFAULT 'active',
                demo          INTEGER NOT NULL DEFAULT 0,
                meta          TEXT NOT NULL DEFAULT '{}'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id  INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
                source        TEXT NOT NULL,
                observed_at   TEXT NOT NULL,
                recorded_at   TEXT NOT NULL,
                confidence    REAL NOT NULL DEFAULT 0,
                severity      TEXT NOT NULL DEFAULT 'info',
                score         INTEGER,
                summary       TEXT DEFAULT '',
                data          TEXT NOT NULL DEFAULT '{}',
                demo          INTEGER NOT NULL DEFAULT 0
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_findings_indicator ON findings(indicator_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source)",
            "CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type)",
            "CREATE INDEX IF NOT EXISTS idx_indicators_severity ON indicators(severity)",
            """
            CREATE TABLE IF NOT EXISTS relationships (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id     INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
                target_id     INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
                kind          TEXT NOT NULL,
                evidence      TEXT DEFAULT '',
                confidence    REAL NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL,
                UNIQUE(source_id, target_id, kind)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS campaigns (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                name                  TEXT NOT NULL UNIQUE,
                description           TEXT DEFAULT '',
                first_seen            TEXT,
                last_seen             TEXT,
                severity              TEXT DEFAULT 'medium',
                confidence            REAL DEFAULT 0,
                attribution           TEXT DEFAULT '',
                attribution_confidence REAL DEFAULT 0,
                tags                  TEXT NOT NULL DEFAULT '[]',
                mitre                 TEXT NOT NULL DEFAULT '[]',
                demo                  INTEGER NOT NULL DEFAULT 0,
                created_at            TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS campaign_indicators (
                campaign_id   INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                indicator_id  INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
                PRIMARY KEY (campaign_id, indicator_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                description   TEXT DEFAULT '',
                status        TEXT NOT NULL DEFAULT 'open',
                priority      TEXT NOT NULL DEFAULT 'medium',
                analyst       TEXT DEFAULT 'analyst',
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                notes         TEXT NOT NULL DEFAULT '[]'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS investigation_items (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id  INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                indicator_id      INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
                added_at          TEXT NOT NULL,
                note              TEXT DEFAULT '',
                UNIQUE(investigation_id, indicator_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS reports (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id   INTEGER,
                title              TEXT NOT NULL,
                path               TEXT NOT NULL,
                format             TEXT NOT NULL DEFAULT 'html',
                summary            TEXT DEFAULT '',
                created_at         TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS events (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT NOT NULL,
                kind     TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                message  TEXT NOT NULL,
                data     TEXT NOT NULL DEFAULT '{}'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS source_status (
                name         TEXT PRIMARY KEY,
                state        TEXT NOT NULL DEFAULT 'unknown',
                last_success TEXT,
                last_error   TEXT,
                requests     INTEGER NOT NULL DEFAULT 0,
                failures     INTEGER NOT NULL DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS cache (
                key        TEXT PRIMARY KEY,
                provider   TEXT NOT NULL,
                payload    TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_cache_expiry ON cache(expires_at)",
            """
            CREATE TABLE IF NOT EXISTS settings (
                key    TEXT PRIMARY KEY,
                value  TEXT NOT NULL
            )
            """,
        ],
    )
]


def init_db(conn: sqlite3.Connection) -> None:
    """Apply all pending migrations. Idempotent."""
    conn.execute("PRAGMA user_version")
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version, _desc, statements in MIGRATIONS:
        if version <= current:
            continue
        for sql in statements:
            conn.execute(sql)
        conn.execute(f"PRAGMA user_version = {version}")
    conn.commit()
