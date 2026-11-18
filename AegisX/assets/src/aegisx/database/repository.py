"""
AegisX — data repository.

Thread-safe (RLock) SQLite persistence layer. All intelligence persistence —
indicators, findings, relationships, campaigns, investigations, reports,
events, provider status, cache and settings — flows through this module.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import init_db

log = logging.getLogger("aegisx.database")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class Repository:
    """Central persistence facade."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=15
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        init_db(self._conn)
        log.info("Database ready at %s", self.db_path)

    # ------------------------------------------------------------------ util
    def _q(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _x(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------ indicators
    def upsert_indicator(
        self,
        value: str,
        type_: str,
        *,
        tags: list[str] | None = None,
        description: str = "",
        country: str = "",
        asn: str = "",
        asn_name: str = "",
        risk_score: int | None = None,
        severity: str | None = None,
        confidence: float | None = None,
        demo: bool = False,
        meta: dict | None = None,
    ) -> int:
        """Insert or update an indicator; returns its id."""
        now = iso()
        existing = self._q("SELECT id, risk_score, confidence FROM indicators WHERE value=?", (value,))
        if existing:
            return existing[0]["id"]

        self._x(
            """INSERT INTO indicators
               (value, type, first_seen, last_seen, risk_score, severity, confidence,
                tags, description, country, asn, asn_name, status, demo, meta)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                value, type_, now, now,
                risk_score if risk_score is not None else 0,
                severity or "info",
                confidence if confidence is not None else 0.0,
                json.dumps(tags or []), description, country, asn, asn_name,
                "active", int(demo), json.dumps(meta or {}),
            ),
        )
        row = self._q("SELECT id FROM indicators WHERE value=?", (value,))[0]
        return row["id"]

    def touch_indicator(self, indicator_id: int, *, meta: dict | None = None,
                        country: str | None = None, asn: str | None = None,
                        asn_name: str | None = None) -> None:
        sets, params = ["last_seen=?"], [iso()]
        if meta is not None:
            sets.append("meta=?"); params.append(json.dumps(meta))
        if country is not None:
            sets.append("country=?"); params.append(country)
        if asn is not None:
            sets.append("asn=?"); params.append(asn)
        if asn_name is not None:
            sets.append("asn_name=?"); params.append(asn_name)
        params.append(indicator_id)
        self._x(f"UPDATE indicators SET {', '.join(sets)} WHERE id=?", tuple(params))

    def score_indicator(self, indicator_id: int, risk_score: int, severity: str,
                        confidence: float) -> None:
        self._x(
            "UPDATE indicators SET risk_score=?, severity=?, confidence=? WHERE id=?",
            (int(risk_score), severity, float(confidence), indicator_id),
        )

    def get_indicator(self, indicator_id: int) -> dict | None:
        rows = self._q("SELECT * FROM indicators WHERE id=?", (indicator_id,))
        return self._indicator_dict(rows[0]) if rows else None

    def get_indicator_by_value(self, value: str) -> dict | None:
        rows = self._q("SELECT * FROM indicators WHERE value=?", (value,))
        return self._indicator_dict(rows[0]) if rows else None

    def search_indicators(
        self,
        *,
        query: str = "",
        type_: str = "",
        severity: str = "",
        source: str = "",
        tag: str = "",
        days: int = 0,
        min_risk: int = 0,
        demo: bool | None = None,
        limit: int = 60,
        offset: int = 0,
        order: str = "risk",
    ) -> list[dict]:
        sql, params = self._indicator_filter_sql(
            query=query, type_=type_, severity=severity, source=source,
            tag=tag, days=days, min_risk=min_risk, demo=demo)
        order_by = {
            "risk": "i.risk_score DESC, i.last_seen DESC",
            "recent": "i.last_seen DESC",
            "value": "i.value ASC",
            "confidence": "i.confidence DESC",
        }.get(order, "i.risk_score DESC, i.last_seen DESC")
        sql += f" GROUP BY i.id ORDER BY {order_by} LIMIT ? OFFSET ?"
        params += [int(limit), int(offset)]
        return [self._indicator_dict(r) for r in self._q(sql, tuple(params))]

    def _indicator_filter_sql(
        self, *, query: str = "", type_: str = "", severity: str = "",
        source: str = "", tag: str = "", days: int = 0,
        min_risk: int = 0, demo: bool | None = None,
    ) -> tuple[str, list]:
        """Shared WHERE builder so search, count and bulk-delete stay in sync."""
        sql = (
            "SELECT DISTINCT i.* FROM indicators i "
            "LEFT JOIN findings f ON f.indicator_id = i.id WHERE 1=1"
        )
        params: list = []
        if query:
            sql += " AND i.value LIKE ?"
            params.append(f"%{query}%")
        if type_:
            sql += " AND i.type=?"
            params.append(type_)
        if severity:
            sql += " AND i.severity=?"
            params.append(severity)
        if source:
            sql += " AND i.id IN (SELECT indicator_id FROM findings WHERE source=?)"
            params.append(source)
        if tag:
            sql += " AND i.tags LIKE ?"
            params.append(f'%"{tag}"%')
        if days:
            cutoff = iso(utcnow() - timedelta(days=days))
            sql += " AND i.last_seen>=?"
            params.append(cutoff)
        if min_risk:
            sql += " AND i.risk_score>=?"
            params.append(int(min_risk))
        if demo is not None:
            sql += " AND i.demo=?"
            params.append(int(demo))
        return sql, params

    def indicator_ids_matching(
        self, *, query: str = "", type_: str = "", severity: str = "",
        source: str = "", tag: str = "", days: int = 0,
        min_risk: int = 0, demo: bool | None = None,
    ) -> list[int]:
        """IDs of every indicator matching the given filters (no limit)."""
        sql, params = self._indicator_filter_sql(
            query=query, type_=type_, severity=severity, source=source,
            tag=tag, days=days, min_risk=min_risk, demo=demo)
        sql += " GROUP BY i.id"
        return [r["id"] for r in self._q(sql, tuple(params))]

    def delete_indicators_batch(self, ids: list[int]) -> int:
        """Delete many indicators by id; returns the number removed."""
        if not ids:
            return 0
        removed = 0
        chunk = 400
        with self._lock:
            for i in range(0, len(ids), chunk):
                part = ids[i:i + chunk]
                marks = ",".join("?" for _ in part)
                cur = self._conn.execute(
                    f"DELETE FROM indicators WHERE id IN ({marks})", part)
                self._conn.commit()
                removed += cur.rowcount
        log.info("Batch deleted %s indicators", removed)
        return removed

    def delete_indicators_matching(
        self, *, query: str = "", type_: str = "", severity: str = "",
        source: str = "", tag: str = "", days: int = 0,
        min_risk: int = 0, demo: bool | None = None,
    ) -> int:
        """Delete every indicator matching the filters; returns count removed."""
        ids = self.indicator_ids_matching(
            query=query, type_=type_, severity=severity, source=source,
            tag=tag, days=days, min_risk=min_risk, demo=demo)
        return self.delete_indicators_batch(ids)

    def count_indicators(self, *, demo: bool | None = None) -> int:
        sql, params = "SELECT COUNT(*) c FROM indicators WHERE 1=1", []
        if demo is not None:
            sql += " AND demo=?"
            params.append(int(demo))
        return self._q(sql, tuple(params))[0]["c"]

    def count_indicators_matching(
        self, *, query: str = "", type_: str = "", severity: str = "",
        source: str = "", tag: str = "", days: int = 0,
        min_risk: int = 0, demo: bool | None = None,
    ) -> int:
        """Count of indicators matching the advanced filters."""
        base_sql, base_params = self._indicator_filter_sql(
            query=query, type_=type_, severity=severity, source=source,
            tag=tag, days=days, min_risk=min_risk, demo=demo)
        inner = base_sql.replace("SELECT DISTINCT i.*", "SELECT DISTINCT i.id", 1)
        inner += " GROUP BY i.id"
        rows = self._q("SELECT COUNT(*) c FROM (" + inner + ")", tuple(base_params))
        return rows[0]["c"] if rows else 0

    def delete_indicator(self, indicator_id: int) -> None:
        self._x("DELETE FROM indicators WHERE id=?", (indicator_id,))

    def add_tag(self, indicator_id: int, tag: str) -> None:
        ind = self.get_indicator(indicator_id)
        if not ind:
            return
        tags = set(ind.get("tags") or [])
        tags.add(tag)
        self._x("UPDATE indicators SET tags=? WHERE id=?", (json.dumps(sorted(tags)), indicator_id))

    def remove_tag(self, indicator_id: int, tag: str) -> None:
        ind = self.get_indicator(indicator_id)
        if not ind:
            return
        tags = set(ind.get("tags") or [])
        tags.discard(tag)
        self._x("UPDATE indicators SET tags=? WHERE id=?", (json.dumps(sorted(tags)), indicator_id))

    def _indicator_dict(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["tags"] = json.loads(d.get("tags") or "[]")
        try:
            d["meta"] = json.loads(d.get("meta") or "{}")
        except json.JSONDecodeError:
            d["meta"] = {}
        return d

    # -------------------------------------------------------------- findings
    def add_finding(self, indicator_id: int, *, source: str, severity: str = "info",
                    confidence: float = 0.0, score: int | None = None,
                    summary: str = "", data: dict | None = None,
                    observed_at: str | None = None, demo: bool = False) -> int:
        now = iso()
        self._x(
            """INSERT INTO findings
               (indicator_id, source, observed_at, recorded_at, confidence, severity,
                score, summary, data, demo)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                indicator_id, source, observed_at or now, now, float(confidence),
                severity, score, summary, json.dumps(data or {}), int(demo),
            ),
        )
        row = self._q(
            "SELECT id FROM findings WHERE indicator_id=? ORDER BY id DESC LIMIT 1",
            (indicator_id,),
        )[0]
        return row["id"]

    def findings_for_indicator(self, indicator_id: int, limit: int = 80) -> list[dict]:
        rows = self._q(
            "SELECT * FROM findings WHERE indicator_id=? ORDER BY recorded_at DESC LIMIT ?",
            (indicator_id, limit),
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["data"] = json.loads(d.get("data") or "{}")
            except json.JSONDecodeError:
                d["data"] = {}
            out.append(d)
        return out

    def sources_for_indicator(self, indicator_id: int) -> list[str]:
        rows = self._q(
            "SELECT DISTINCT source FROM findings WHERE indicator_id=?", (indicator_id,)
        )
        return [r["source"] for r in rows]

    # ---------------------------------------------------------- relationships
    def add_relationship(self, source_id: int, target_id: int, kind: str,
                         evidence: str = "", confidence: float = 0.0) -> bool:
        if source_id == target_id:
            return False
        try:
            self._x(
                """INSERT INTO relationships (source_id, target_id, kind, evidence,
                   confidence, created_at) VALUES (?,?,?,?,?,?)""",
                (source_id, target_id, kind, evidence, float(confidence), iso()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def relationships_for(self, indicator_id: int, depth: int = 1) -> list[dict]:
        rows = self._q(
            """SELECT r.*, i1.value AS source_value, i1.type AS source_type,
                      i2.value AS target_value, i2.type AS target_type,
                      i2.risk_score AS target_risk, i2.severity AS target_severity
               FROM relationships r
               JOIN indicators i1 ON i1.id = r.source_id
               JOIN indicators i2 ON i2.id = r.target_id
               WHERE r.source_id=? OR r.target_id=?""",
            (indicator_id, indicator_id),
        )
        return [dict(r) for r in rows]

    def relationship_count(self) -> int:
        return self._q("SELECT COUNT(*) c FROM relationships")[0]["c"]

    def recent_relationships(self, limit: int = 12) -> list[dict]:
        rows = self._q(
            """SELECT r.*, i1.value AS source_value, i2.value AS target_value
               FROM relationships r
               JOIN indicators i1 ON i1.id=r.source_id
               JOIN indicators i2 ON i2.id=r.target_id
               ORDER BY r.created_at DESC LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- campaigns
    def upsert_campaign(self, name: str, *, description: str = "", first_seen: str = "",
                        last_seen: str = "", severity: str = "medium",
                        confidence: float = 0.0, attribution: str = "",
                        attribution_confidence: float = 0.0, tags: list[str] | None = None,
                        mitre: list[str] | None = None, demo: bool = False) -> int:
        rows = self._q("SELECT id FROM campaigns WHERE name=?", (name,))
        if rows:
            cid = rows[0]["id"]
            self._x(
                """UPDATE campaigns SET
                   description=CASE WHEN ?!='' THEN ? ELSE description END,
                   first_seen=COALESCE(NULLIF(?,''), first_seen),
                   last_seen=CASE WHEN ?!='' THEN ? ELSE last_seen END,
                   severity=CASE WHEN ?!='' THEN ? ELSE severity END,
                   confidence=CASE WHEN ? THEN ? ELSE confidence END,
                   attribution=COALESCE(NULLIF(?,''), attribution),
                   attribution_confidence=CASE WHEN ? THEN ? ELSE attribution_confidence END,
                   tags=CASE WHEN ? THEN ? ELSE tags END,
                   mitre=CASE WHEN ? THEN ? ELSE mitre END
                   WHERE id=?""",
                (
                    description, description, first_seen, last_seen, last_seen,
                    severity, severity,
                    confidence is not None, float(confidence if confidence is not None else 0),
                    attribution,
                    attribution_confidence is not None,
                    float(attribution_confidence if attribution_confidence is not None else 0),
                    tags is not None, json.dumps(tags or []),
                    mitre is not None, json.dumps(mitre or []),
                    cid,
                ),
            )
            return cid
        self._x(
            """INSERT INTO campaigns (name, description, first_seen, last_seen, severity,
               confidence, attribution, attribution_confidence, tags, mitre, demo, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                name, description, first_seen or iso(), last_seen or iso(), severity,
                float(confidence), attribution, float(attribution_confidence),
                json.dumps(tags or []), json.dumps(mitre or []), int(demo), iso(),
            ),
        )
        return self._q("SELECT id FROM campaigns WHERE name=?", (name,))[0]["id"]

    def list_campaigns(self, demo: bool | None = None) -> list[dict]:
        sql = "SELECT * FROM campaigns"
        params: tuple = ()
        if demo is not None:
            sql += " WHERE demo=?"
            params = (int(demo),)
        sql += " ORDER BY last_seen DESC"
        out = []
        for r in self._q(sql, params):
            d = dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            d["mitre"] = json.loads(d.get("mitre") or "[]")
            d["indicator_count"] = self._q(
                "SELECT COUNT(*) c FROM campaign_indicators WHERE campaign_id=?",
                (d["id"],),
            )[0]["c"]
            out.append(d)
        return out

    def get_campaign(self, campaign_id: int) -> dict | None:
        rows = self._q("SELECT * FROM campaigns WHERE id=?", (campaign_id,))
        if not rows:
            return None
        d = dict(rows[0])
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["mitre"] = json.loads(d.get("mitre") or "[]")
        d["indicator_count"] = self._q(
            "SELECT COUNT(*) c FROM campaign_indicators WHERE campaign_id=?", (d["id"],)
        )[0]["c"]
        return d

    def link_campaign_indicator(self, campaign_id: int, indicator_id: int) -> None:
        try:
            self._x(
                "INSERT OR IGNORE INTO campaign_indicators (campaign_id, indicator_id) VALUES (?,?)",
                (campaign_id, indicator_id),
            )
        except sqlite3.IntegrityError:
            pass

    def unlink_campaign_indicator(self, campaign_id: int, indicator_id: int) -> None:
        self._x(
            "DELETE FROM campaign_indicators WHERE campaign_id=? AND indicator_id=?",
            (campaign_id, indicator_id),
        )

    def campaign_indicators(self, campaign_id: int) -> list[dict]:
        rows = self._q(
            """SELECT i.* FROM campaign_indicators ci JOIN indicators i ON i.id=ci.indicator_id
               WHERE ci.campaign_id=? ORDER BY i.risk_score DESC""",
            (campaign_id,),
        )
        return [self._indicator_dict(r) for r in rows]

    # ---------------------------------------------------------- investigations
    def create_investigation(self, name: str, *, description: str = "",
                             priority: str = "medium", analyst: str = "analyst") -> int:
        now = iso()
        self._x(
            """INSERT INTO investigations (name, description, status, priority, analyst,
               created_at, updated_at, notes) VALUES (?,?,?,?,?,?,?,?)""",
            (name, description, "open", priority, analyst, now, now, "[]"),
        )
        return self._q("SELECT id FROM investigations WHERE name=? ORDER BY id DESC LIMIT 1", (name,))[0]["id"]

    def list_investigations(self) -> list[dict]:
        rows = self._q(
            """SELECT i.*, (SELECT COUNT(*) FROM investigation_items x
               WHERE x.investigation_id=i.id) AS item_count
               FROM investigations i ORDER BY i.updated_at DESC"""
        )
        out = []
        for r in rows:
            d = dict(r)
            d["notes"] = json.loads(d.get("notes") or "[]")
            out.append(d)
        return out

    def get_investigation(self, investigation_id: int) -> dict | None:
        rows = self._q("SELECT * FROM investigations WHERE id=?", (investigation_id,))
        if not rows:
            return None
        d = dict(rows[0])
        d["notes"] = json.loads(d.get("notes") or "[]")
        return d

    def update_investigation(self, investigation_id: int, **fields) -> None:
        allowed = ("name", "description", "status", "priority", "analyst")
        sets, params = ["updated_at=?"], [iso()]
        for k, v in fields.items():
            if k in allowed and v is not None:
                sets.append(f"{k}=?")
                params.append(str(v))
        params.append(investigation_id)
        self._x(f"UPDATE investigations SET {', '.join(sets)} WHERE id=?", tuple(params))

    def delete_investigation(self, investigation_id: int) -> None:
        self._x("DELETE FROM investigations WHERE id=?", (investigation_id,))

    def add_note(self, investigation_id: int, author: str, text: str) -> None:
        inv = self.get_investigation(investigation_id)
        if not inv:
            return
        notes = inv.get("notes") or []
        notes.append({"ts": iso(), "author": author, "text": text})
        self._x("UPDATE investigations SET notes=?, updated_at=? WHERE id=?",
                (json.dumps(notes), iso(), investigation_id))

    def add_investigation_item(self, investigation_id: int, indicator_id: int,
                               note: str = "") -> bool:
        try:
            self._x(
                """INSERT INTO investigation_items (investigation_id, indicator_id,
                   added_at, note) VALUES (?,?,?,?)""",
                (investigation_id, indicator_id, iso(), note),
            )
            self._x("UPDATE investigations SET updated_at=? WHERE id=?",
                    (iso(), investigation_id))
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_investigation_item(self, investigation_id: int, indicator_id: int) -> None:
        self._x(
            "DELETE FROM investigation_items WHERE investigation_id=? AND indicator_id=?",
            (investigation_id, indicator_id),
        )

    def investigation_items(self, investigation_id: int) -> list[dict]:
        rows = self._q(
            """SELECT i.*, x.added_at AS item_added_at, x.note AS item_note
               FROM investigation_items x JOIN indicators i ON i.id=x.indicator_id
               WHERE x.investigation_id=? ORDER BY x.added_at DESC""",
            (investigation_id,),
        )
        out = []
        for r in rows:
            d = self._indicator_dict(r)
            d["item_added_at"] = r["item_added_at"]
            d["item_note"] = r["item_note"]
            out.append(d)
        return out

    def open_investigation_count(self) -> int:
        return self._q(
            "SELECT COUNT(*) c FROM investigations WHERE status IN ('open','active')"
        )[0]["c"]

    # ---------------------------------------------------------------- reports
    def add_report(self, title: str, path: str, format_: str,
                   investigation_id: int | None = None, summary: str = "") -> int:
        self._x(
            """INSERT INTO reports (investigation_id, title, path, format, summary, created_at)
               VALUES (?,?,?,?,?,?)""",
            (investigation_id, title, path, format_, summary, iso()),
        )
        return self._q("SELECT id FROM reports ORDER BY id DESC LIMIT 1")[0]["id"]

    def list_reports(self) -> list[dict]:
        return [dict(r) for r in self._q("SELECT * FROM reports ORDER BY created_at DESC LIMIT 200")]

    def delete_report(self, report_id: int) -> None:
        row = self._q("SELECT path FROM reports WHERE id=?", (report_id,))
        if row:
            p = Path(row[0]["path"])
            try:
                if p.is_file():
                    p.unlink()
            except OSError:
                pass
        self._x("DELETE FROM reports WHERE id=?", (report_id,))

    # ------------------------------------------------------------------ events
    def add_event(self, kind: str, message: str, severity: str = "info", data: dict | None = None) -> None:
        self._x(
            "INSERT INTO events (ts, kind, severity, message, data) VALUES (?,?,?,?,?)",
            (iso(), kind, severity, message, json.dumps(data or {})),
        )

    def recent_events(self, limit: int = 40) -> list[dict]:
        rows = self._q("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["data"] = json.loads(d.get("data") or "{}")
            except json.JSONDecodeError:
                d["data"] = {}
            out.append(d)
        return out

    # ------------------------------------------------------------ source status
    def set_source_state(self, name: str, state: str, *, error: str = "") -> None:
        now = iso()
        existing = self._q("SELECT requests, failures FROM source_status WHERE name=?", (name,))
        if existing:
            err = error or None
            if state == "online":
                self._x(
                    "UPDATE source_status SET state=?, last_success=?, last_error=COALESCE(?, last_error) WHERE name=?",
                    (state, now, err, name),
                )
            else:
                self._x(
                    "UPDATE source_status SET state=?, last_error=?, failures=failures+1 WHERE name=?",
                    (state, err or "unknown error", name),
                )
        else:
            self._x(
                "INSERT INTO source_status (name, state, last_success, last_error, requests, failures)"
                " VALUES (?,?,?,?,0,?)",
                (name, state, now if state == "online" else None, error, 1 if state != "online" else 0),
            )

    def bump_source_counters(self, name: str, *, request: bool = True, failure: bool = False) -> None:
        existing = self._q("SELECT name FROM source_status WHERE name=?", (name,))
        if not existing:
            self._x("INSERT INTO source_status (name, state) VALUES (?, 'unknown')", (name,))
        if failure:
            self._x("UPDATE source_status SET requests=requests+1, failures=failures+1 WHERE name=?", (name,))
        elif request:
            self._x("UPDATE source_status SET requests=requests+1 WHERE name=?", (name,))

    def source_states(self) -> list[dict]:
        return [dict(r) for r in self._q("SELECT * FROM source_status ORDER BY name")]

    # ------------------------------------------------------------------- cache
    def cache_get(self, key: str) -> dict | None:
        rows = self._q("SELECT payload, expires_at, created_at FROM cache WHERE key=?", (key,))
        if not rows:
            return None
        r = rows[0]
        if r["expires_at"] <= iso():
            self._x("DELETE FROM cache WHERE key=?", (key,))
            return None
        try:
            return {"payload": json.loads(r["payload"]), "created_at": r["created_at"]}
        except json.JSONDecodeError:
            return None

    def cache_set(self, key: str, provider: str, payload: dict, ttl_seconds: int) -> None:
        now = utcnow()
        self._x(
            "INSERT OR REPLACE INTO cache (key, provider, payload, created_at, expires_at)"
            " VALUES (?,?,?,?,?)",
            (key, provider, json.dumps(payload), iso(now), iso(now + timedelta(seconds=ttl_seconds))),
        )

    def cache_clear(self) -> int:
        n = self._q("SELECT COUNT(*) c FROM cache")[0]["c"]
        self._x("DELETE FROM cache")
        return n

    def cache_stats(self) -> dict:
        row = self._q("SELECT COUNT(*) c, COALESCE(SUM(LENGTH(payload)),0) s FROM cache")[0]
        return {"entries": row["c"], "bytes": row["s"]}

    def cache_purge_expired(self) -> int:
        return self._x("DELETE FROM cache WHERE expires_at <= ?", (iso(),))

    # ---------------------------------------------------------------- settings
    def get_setting(self, key: str, default: str = "") -> str:
        rows = self._q("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def set_setting(self, key: str, value: str) -> None:
        self._x("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value)))

    def all_settings(self) -> dict:
        return {r["key"]: r["value"] for r in self._q("SELECT * FROM settings")}

    # ------------------------------------------------------------------- stats
    def stats(self, demo: bool | None = None) -> dict:
        cond = " WHERE demo=?" if demo is not None else ""
        params: tuple = ((int(demo),) if demo is not None else ())
        counts = self._q(
            f"""SELECT COUNT(*) total,
                       SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) high_risk,
                       SUM(CASE WHEN type IN ('ip','ipv6') THEN 1 ELSE 0 END) ips,
                       SUM(CASE WHEN type='domain' THEN 1 ELSE 0 END) domains,
                       SUM(CASE WHEN type='url' THEN 1 ELSE 0 END) urls,
                       SUM(CASE WHEN type='hash' THEN 1 ELSE 0 END) hashes,
                       AVG(confidence) avg_confidence,
                       AVG(risk_score) avg_risk
                FROM indicators{cond}""",
            params,
        )[0]
        return {
            "total": counts["total"] or 0,
            "high_risk": counts["high_risk"] or 0,
            "ips": counts["ips"] or 0,
            "domains": counts["domains"] or 0,
            "urls": counts["urls"] or 0,
            "hashes": counts["hashes"] or 0,
            "avg_confidence": round(counts["avg_confidence"] or 0, 3),
            "avg_risk": round(counts["avg_risk"] or 0, 1),
            "investigations": self.open_investigation_count(),
            "campaigns": len(self.list_campaigns()),
            "relationships": self.relationship_count(),
        }

    def severity_distribution(self, demo: bool | None = None) -> dict:
        cond, params = "", []
        if demo is not None:
            cond = " WHERE demo=?"
            params.append(int(demo))
        rows = self._q(
            f"SELECT severity, COUNT(*) c FROM indicators{cond} GROUP BY severity", tuple(params)
        )
        return {r["severity"]: r["c"] for r in rows}

    def type_distribution(self, demo: bool | None = None) -> dict:
        cond, params = "", []
        if demo is not None:
            cond = " WHERE demo=?"
            params.append(int(demo))
        rows = self._q(
            f"SELECT type, COUNT(*) c FROM indicators{cond} GROUP BY type ORDER BY c DESC", tuple(params)
        )
        return {r["type"]: r["c"] for r in rows}

    def activity_timeline(self, days: int = 30, demo: bool | None = None) -> list[dict]:
        cutoff = iso(utcnow() - timedelta(days=days))
        cond, params = "", []
        if demo is not None:
            cond = " AND demo=?"
            params.append(int(demo))
        rows = self._q(
            f"""SELECT substr(last_seen,1,10) day, COUNT(*) c FROM indicators
                WHERE last_seen>=?{cond} GROUP BY day ORDER BY day""",
            (cutoff, *params),
        )
        return [{"day": r["day"], "count": r["c"]} for r in rows]

    def top_field(self, field: str, limit: int = 8, demo: bool | None = None) -> list[dict]:
        assert field in ("country", "asn", "asn_name"), field
        where = ["t." + field + " != ''"]
        params: list = []
        if demo is not None:
            where.append("t.demo=?")
            params.append(int(demo))
        rows = self._q(
            f"""SELECT {field} k, COUNT(*) c, AVG(risk_score) avg_risk FROM indicators t
                WHERE {' AND '.join(where)} GROUP BY {field} ORDER BY c DESC LIMIT ?""",
            (*params, limit),
        )
        return [{"key": r["k"], "count": r["c"], "avg_risk": round(r["avg_risk"] or 0)} for r in rows]

    def source_contribution(self) -> list[dict]:
        rows = self._q(
            "SELECT source, COUNT(DISTINCT indicator_id) c FROM findings GROUP BY source ORDER BY c DESC"
        )
        return [{"source": r["source"], "count": r["c"]} for r in rows]

    def confidence_histogram(self, demo: bool | None = None, buckets: int = 5) -> list[dict]:
        cond, params = "", []
        if demo is not None:
            cond = " WHERE demo=?"
            params.append(int(demo))
        rows = self._q(f"SELECT confidence FROM indicators{cond}", tuple(params))
        hist = [0] * buckets
        for r in rows:
            idx = min(buckets - 1, int((r["confidence"] or 0) * buckets))
            hist[idx] += 1
        return [{"bucket": f"{i / buckets:.0%}-{(i + 1) / buckets:.0%}", "count": c} for i, c in enumerate(hist)]

    def wipe_all(self) -> None:
        with self._lock:
            for table in (
                "findings", "relationships", "campaign_indicators", "campaigns",
                "investigation_items", "investigations", "reports", "events",
                "source_status", "cache", "indicators",
            ):
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.commit()
        log.warning("Database wiped by analyst action.")

    def export_all(self) -> dict:
        return {
            "exported_at": iso(),
            "indicators": [self._indicator_dict(r) for r in self._q("SELECT * FROM indicators")],
            "campaigns": self.list_campaigns(),
            "investigations": self.list_investigations(),
            "events": self.recent_events(500),
        }


def migrate(db_path: Path) -> Repository:
    repo = Repository(db_path)
    return repo
