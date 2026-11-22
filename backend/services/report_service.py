"""Weekly reports for SERC (enhancement 04).

Summarises the alerts analysts submitted during one calendar week (Monday 00:00 to Sunday 23:59, UTC) using the
alert history. Everything in the report is counted or copied from stored data. The plain-language "points to
check" are produced by fixed rules from those counts, not by a model, so they can be traced and tested.
"""
from __future__ import annotations

import csv
import io
import logging
from collections import Counter
from datetime import date, datetime, time as dtime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.services.history_service import HistoryStore, SEVERITIES, utc_now

logger = logging.getLogger("serc.reports")

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
TOP_N = 5
NOTABLE_N = 10


def monday_of(d: date) -> date:
    return d - timedelta(days=d.weekday())


def week_window(week_start: date) -> tuple[datetime, datetime]:
    start = datetime.combine(monday_of(week_start), dtime.min, tzinfo=timezone.utc)
    return start, start + timedelta(days=7)


def _label(start: date) -> str:
    end = start + timedelta(days=6)
    return f"{start.strftime('%d %b')} – {end.strftime('%d %b %Y')}"


def _top(counter: Counter, n: int = TOP_N) -> List[tuple]:
    return sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:n]


def _summarise(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    sev = Counter(r["severity"] if r["severity"] in SEVERITIES else "Unknown" for r in rows)
    hi = sev["High"] + sev["Critical"]
    return {"alerts": len(rows), "high_critical": hi, "severity": {s: sev.get(s, 0) for s in SEVERITIES}}


def _delta(now: int, before: int) -> Dict[str, Any]:
    return {"now": now, "before": before, "change": now - before,
            "percent": None if before == 0 else round((now - before) * 100 / before)}


def build_weekly_report(store: HistoryStore, week_start: Optional[date] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utc_now()
    start_day = monday_of(week_start or now.date())
    start, end = week_window(start_day)
    rows = store.between(start, end)
    prev_start, prev_end = week_window(start_day - timedelta(days=7))
    prev_rows = store.between(prev_start, prev_end)
    partial = start <= now < end

    cur = _summarise(rows)
    prev = _summarise(prev_rows)

    # per day
    per_day = []
    for i in range(7):
        d = start_day + timedelta(days=i)
        day_rows = [r for r in rows if r["submitted_at"][:10] == d.isoformat()]
        per_day.append({"date": d.isoformat(), "label": DAY_NAMES[i], "count": len(day_rows),
                        "high_critical": sum(1 for r in day_rows if r["severity"] in ("High", "Critical"))})

    rules: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if not r["rule_id"]:
            continue
        e = rules.setdefault(r["rule_id"], {"rule_id": r["rule_id"], "description": r["description"], "count": 0, "max_level": None})
        e["count"] += 1
        if r["level"] is not None and (e["max_level"] is None or r["level"] > e["max_level"]):
            e["max_level"] = r["level"]
    top_rules = sorted(rules.values(), key=lambda e: (-e["count"], e["rule_id"]))[:TOP_N]

    techniques = Counter(t for r in rows for t in set(r["mitre_ids"]))
    hosts = Counter(r["agent_name"] for r in rows if r["agent_name"])
    sources = Counter(r["srcip"] for r in rows if r["srcip"])
    inputs = Counter(r["source_type"] or "unknown" for r in rows)
    analysts = Counter(r["username"] for r in rows if r["username"])
    scores = [r["verification_score"] for r in rows if r["verification_score"] is not None]

    notable = [r for r in rows if r["severity"] in ("High", "Critical")]
    notable.sort(key=lambda r: ((r["level"] if r["level"] is not None else -1), r["submitted_at"]), reverse=True)
    notable_out = [{"history_id": r["id"], "time": r["submitted_at"], "severity": r["severity"], "level": r["level"],
                    "description": r["description"], "host": r["agent_name"], "rule_id": r["rule_id"],
                    "analyst": r["username"]} for r in notable[:NOTABLE_N]]

    report: Dict[str, Any] = {
        "week": {"start": start_day.isoformat(), "end": (start_day + timedelta(days=6)).isoformat(), "label": _label(start_day),
                 "partial": partial, "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"), "timezone": "UTC"},
        "totals": {"alerts": cur["alerts"], "distinct_alerts": len({r["alert_id"] for r in rows}), "analysts": len(analysts),
                   "high_critical": cur["high_critical"], "average_verification": round(sum(scores) / len(scores)) if scores else None,
                   "needs_attention": sum(r["needs_attention"] for r in rows)},
        "severity": cur["severity"],
        "per_day": per_day,
        "top_rules": top_rules,
        "top_techniques": [{"id": k, "count": v} for k, v in _top(techniques)],
        "top_hosts": [{"name": k, "count": v} for k, v in _top(hosts)],
        "top_sources": [{"ip": k, "count": v} for k, v in _top(sources)],
        "inputs": dict(_top(inputs, 10)),
        "analysts": [{"name": k, "count": v} for k, v in _top(analysts, 10)],
        "notable": notable_out,
        "comparison": {"alerts": _delta(cur["alerts"], prev["alerts"]),
                       "high_critical": _delta(cur["high_critical"], prev["high_critical"]),
                       "previous_week": _label(start_day - timedelta(days=7))},
    }
    report["insights"] = _insights(report)
    return report


def _insights(rep: Dict[str, Any]) -> List[str]:
    t, out = rep["totals"], []
    if t["alerts"] == 0:
        return ["No alerts were analysed in this week."]
    busiest = max(rep["per_day"], key=lambda d: d["count"])
    if busiest["count"] > 0:
        out.append(f"Busiest day: {busiest['label']} {busiest['date']} with {busiest['count']} alert(s).")
    if rep["top_rules"]:
        r = rep["top_rules"][0]
        out.append(f"Most frequent rule: {r['rule_id']} ({r['description'][:80]}) appeared {r['count']} time(s).")
    c = rep["comparison"]["alerts"]
    if c["before"] and c["percent"] is not None and abs(c["percent"]) >= 25 and max(c["now"], c["before"]) >= 4:
        out.append(f"Alert volume is {'up' if c['change'] > 0 else 'down'} {abs(c['percent'])}% compared with the week of "
                   f"{rep['comparison']['previous_week']}.")
    if rep["totals"]["needs_attention"]:
        out.append(f"{rep['totals']['needs_attention']} statement(s) across these analyses were flagged for a human look in the Verification tab.")
    if rep["week"]["partial"]:
        out.append("This week is still in progress, so the figures are not final.")
    return out


# ------------------------------------------------------------------ outputs
def _table(headers: List[str], rows: List[List[Any]]) -> List[str]:
    if not rows:
        return ["_None_", ""]
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in rows]
    return out + [""]



def to_markdown(rep: Dict[str, Any]) -> str:
    w, t = rep["week"], rep["totals"]
    L = [f"# SERC weekly security report", "", f"**Week:** {w['label']} (UTC){' – in progress' if w['partial'] else ''}",
         f"**Generated:** {w['generated_at']}", "", "## Overview", "",
         f"- Alerts analysed: **{t['alerts']}** ({t['distinct_alerts']} distinct) by {t['analysts']} analyst(s)",
         f"- High or critical: **{t['high_critical']}**"]
    if t["average_verification"] is not None:
        L.append(f"- Average verification score: {t['average_verification']}%")
    c = rep["comparison"]
    for key, label in (("alerts", "Alerts"), ("high_critical", "High or critical")):
        x = c[key]
        pct = "" if x["percent"] is None else f" ({x['percent']:+d}%)"
        L.append(f"- {label}: {x['now']} this week vs {x['before']} in the week of {c['previous_week']}{pct}")
    L += ["", "## Points to check", ""] + [f"- {i}" for i in rep["insights"]] + ["", "## Alerts by severity", ""]
    L += _table(["Severity", "Alerts"], [[s, n] for s, n in rep["severity"].items()])
    L += ["## Alerts per day", ""] + _table(["Day", "Date", "Alerts", "High/Critical"], [[d["label"], d["date"], d["count"], d["high_critical"]] for d in rep["per_day"]])
    L += ["## Top rules", ""] + _table(["Rule", "Description", "Alerts", "Highest level"], [[r["rule_id"], r["description"][:90], r["count"], r["max_level"] if r["max_level"] is not None else "–"] for r in rep["top_rules"]])
    L += ["## Top ATT&CK techniques", ""] + _table(["Technique", "Alerts"], [[x["id"], x["count"]] for x in rep["top_techniques"]])
    L += ["## Most affected hosts", ""] + _table(["Host", "Alerts"], [[x["name"], x["count"]] for x in rep["top_hosts"]])
    L += ["## Most frequent source IPs", ""] + _table(["Source IP", "Alerts"], [[x["ip"], x["count"]] for x in rep["top_sources"]])
    L += ["## High and critical alerts", ""] + _table(["Time (UTC)", "Severity", "Description", "Host", "Analyst"],
          [[n["time"], n["severity"], n["description"][:90], n["host"] or "–", n["analyst"] or "–"] for n in rep["notable"]])
    L += ["---", "Counts come from the SERC alert history. SERC is decision support, not an automatic responder."]
    return "\n".join(L) + "\n"


CSV_HEADERS = ["time_utc", "analyst", "alert_id", "severity", "level", "rule_id", "description", "host", "source_ip", "user",
               "mitre", "verification_score", "input_type", "mode"]


def _csv_safe(value: Any) -> Any:
    """Stop spreadsheet programs from running text that starts with = + - @ as a formula."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def rows_to_csv(rows: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_HEADERS)
    for r in rows:
        w.writerow([_csv_safe(x) for x in (
            r["submitted_at"], r["username"], r["alert_id"], r["severity"], "" if r["level"] is None else r["level"], r["rule_id"],
            r["description"], r["agent_name"], r["srcip"], r["srcuser"], " ".join(r["mitre_ids"]),
            "" if r["verification_score"] is None else r["verification_score"], r["source_type"], r["mode"])])
    return buf.getvalue()


def available_weeks(store: HistoryStore, count: int = 8, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    now = now or utc_now()
    this_monday = monday_of(now.date())
    out = []
    for i in range(count):
        d = this_monday - timedelta(days=7 * i)
        s, e = week_window(d)
        out.append({"start": d.isoformat(), "label": _label(d) + (" (this week)" if i == 0 else ""), "alerts": len(store.between(s, e))})
    return out


# ------------------------------------------------------------------ periodic saving
def ensure_saved_reports(store: HistoryStore, directory: Path, weeks_back: int = 4, now: Optional[datetime] = None) -> List[str]:
    """Save a Markdown report for each finished recent week that had alerts and has no file yet.
    A finished week never changes (apart from late analyst decisions), so existing files are left alone."""
    now = now or utc_now()
    directory = Path(directory)
    saved: List[str] = []
    this_monday = monday_of(now.date())
    for i in range(1, weeks_back + 1):
        d = this_monday - timedelta(days=7 * i)
        iso = d.isocalendar()
        path = directory / f"weekly-{iso[0]}-W{iso[1]:02d}.md"
        if path.exists():
            continue
        rep = build_weekly_report(store, d, now)
        if rep["totals"]["alerts"] == 0:
            continue
        directory.mkdir(parents=True, exist_ok=True)
        path.write_text(to_markdown(rep), encoding="utf-8")
        saved.append(path.name)
    return saved
