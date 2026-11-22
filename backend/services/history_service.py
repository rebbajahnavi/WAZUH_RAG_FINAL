"""Alert history for SERC (enhancement 01).

Every alert an analyst submits for analysis is saved together with its full result, so it can be found again,
reopened without running the analysis a second time, filtered, exported and counted in the weekly report.

Storage is the same SQLite file as the analyst feedback (``feedback.db``). Times are stored in UTC.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SEVERITIES = ("Low", "Medium", "High", "Critical", "Unknown")
MAX_PAGE = 200

_LIST_COLUMNS = (
    "h.id, h.alert_id, h.username, h.submitted_at, h.source_type, h.rule_id, h.level, h.severity, h.description, "
    "h.agent_name, h.srcip, h.srcuser, h.mitre_ids, h.verification_score, h.needs_attention, h.mode"
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fmt_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class HistoryStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._ready = False

    @contextmanager
    def _conn(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            if not self._ready:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS alert_history (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           alert_id TEXT NOT NULL,
                           username TEXT NOT NULL DEFAULT '',
                           submitted_at TEXT NOT NULL,
                           source_type TEXT NOT NULL DEFAULT '',
                           rule_id TEXT NOT NULL DEFAULT '',
                           level INTEGER,
                           severity TEXT NOT NULL DEFAULT 'Unknown',
                           description TEXT NOT NULL DEFAULT '',
                           agent_name TEXT NOT NULL DEFAULT '',
                           srcip TEXT NOT NULL DEFAULT '',
                           srcuser TEXT NOT NULL DEFAULT '',
                           mitre_ids TEXT NOT NULL DEFAULT '',
                           verification_score INTEGER,
                           needs_attention INTEGER NOT NULL DEFAULT 0,
                           mode TEXT NOT NULL DEFAULT '',
                           alert_json TEXT NOT NULL,
                           result_json TEXT NOT NULL
                       )""")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_hist_time ON alert_history(submitted_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_hist_alert ON alert_history(alert_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_hist_user ON alert_history(username)")
                self._ready = True
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ write
    def record(self, username: str, alert: Dict[str, Any], result: Dict[str, Any], source_type: str = "",
               now: Optional[datetime] = None) -> int:
        """Save one analysed alert. Returns the history id."""
        a = result.get("alert") or {}
        val = result.get("validation") or {}
        row = (
            str(a.get("alert_id") or "")[:120], (username or "")[:64], fmt_time(now or utc_now()), (source_type or "")[:30],
            str(a.get("rule_id") or "")[:60], a.get("level"), str(a.get("severity") or "Unknown")[:20],
            str(a.get("description") or "")[:300], str(a.get("agent_name") or "")[:120], str(a.get("srcip") or "")[:64],
            str(a.get("srcuser") or "")[:120], ",".join(a.get("mitre_ids") or [])[:200],
            val.get("verification_score"), int(val.get("needs_attention") or 0), str(result.get("mode") or ""),
            json.dumps(alert, default=str), json.dumps(result, default=str),
        )
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO alert_history (alert_id, username, submitted_at, source_type, rule_id, level, severity, description, "
                "agent_name, srcip, srcuser, mitre_ids, verification_score, needs_attention, mode, alert_json, result_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
            return int(cur.lastrowid)

    def delete(self, history_id: int, username: str, is_admin: bool = False) -> bool:
        """Analysts delete their own entries; admins can delete any."""
        with self._conn() as c:
            if is_admin:
                cur = c.execute("DELETE FROM alert_history WHERE id=?", (history_id,))
            else:
                cur = c.execute("DELETE FROM alert_history WHERE id=? AND username=?", (history_id, username))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ read
    def _filters(self, username: Optional[str], q: str, severity: str, since: str):
        where, args = ["1=1"], []
        if username:
            where.append("h.username = ?"); args.append(username)
        if severity and severity in SEVERITIES:
            where.append("h.severity = ?"); args.append(severity)
        if since:
            where.append("h.submitted_at >= ?"); args.append(since)
        if q.strip():
            like = _like(q.strip()[:80])
            where.append("(" + " OR ".join(f"h.{col} LIKE ? ESCAPE '\\'" for col in
                         ("description", "agent_name", "srcip", "srcuser", "rule_id", "alert_id", "mitre_ids", "username")) + ")")
            args += [like] * 8
        return " AND ".join(where), args

    def list(self, username: Optional[str] = None, q: str = "", severity: str = "", since: str = "",
             limit: int = 25, offset: int = 0) -> Dict[str, Any]:
        limit = max(1, min(int(limit), MAX_PAGE)); offset = max(0, int(offset))
        with self._conn() as c:
            where, args = self._filters(username, q, severity, since)
            total = c.execute(f"SELECT COUNT(*) FROM alert_history h WHERE {where}", args).fetchone()[0]
            rows = c.execute(f"SELECT {_LIST_COLUMNS} FROM alert_history h WHERE {where} "
                             f"ORDER BY h.submitted_at DESC, h.id DESC LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
        return {"total": int(total), "limit": limit, "offset": offset, "items": [self._item(r) for r in rows]}

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["mitre_ids"] = [m for m in (d.get("mitre_ids") or "").split(",") if m]
        d["needs_attention"] = int(d.get("needs_attention") or 0)
        return d

    def get(self, history_id: int) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute(f"SELECT {_LIST_COLUMNS}, h.alert_json, h.result_json FROM alert_history h WHERE h.id=?",
                            (history_id,)).fetchone()
        if not row:
            return None
        item = self._item(row)
        alert_json, result_json = item.pop("alert_json"), item.pop("result_json")
        item["alert"], item["result"] = json.loads(alert_json), json.loads(result_json)
        return item

    def between(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        """All rows with start <= submitted_at < end (for reports)."""
        with self._conn() as c:
            rows = c.execute(f"SELECT {_LIST_COLUMNS} FROM alert_history h "
                             f"WHERE h.submitted_at >= ? AND h.submitted_at < ? ORDER BY h.submitted_at, h.id",
                             (fmt_time(start), fmt_time(end))).fetchall()
        return [self._item(r) for r in rows]

    def count(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM alert_history").fetchone()[0])
