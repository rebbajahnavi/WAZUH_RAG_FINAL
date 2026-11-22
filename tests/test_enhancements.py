"""Tests for the four enhancements: alert history, synchronized dataset, guided input form, weekly reports.
They need no server, model or real knowledge base.   Run from the project root:   python -m pytest tests/test_enhancements.py -v
"""
import hashlib
import json
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.services import alert_parser as ap
from backend.services import report_service as rs
from backend.services.dataset_sync import DatasetSync, record_hash
from backend.services.history_service import HistoryStore


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp())


def fake_result(severity="High", level=10, rule="5710", desc="sshd: attempt to login using a non-existent user", host="web-01",
                ip="203.0.113.5", mitre=("T1110",), verification=80, attention=1, alert_id="a-1"):
    return {"mode": "offline", "alert": {"alert_id": alert_id, "rule_id": rule, "level": level, "severity": severity, "description": desc,
            "agent_name": host, "srcip": ip, "srcuser": "root", "mitre_ids": list(mitre)},
            "validation": {"verification_score": verification, "needs_attention": attention}}


T0 = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)   # a Wednesday


# ------------------------------------------------------------------ 01 alert history
def test_history_record_list_get_roundtrip():
    h = HistoryStore(tmpdir() / "f.db")
    alert = {"id": "a-1", "rule": {"id": "5710"}}
    hid = h.record("alice", alert, fake_result(), "form", now=T0)
    page = h.list()
    assert page["total"] == 1 and page["items"][0]["id"] == hid
    item = h.get(hid)
    assert item["alert"] == alert and item["result"]["alert"]["rule_id"] == "5710"
    assert item["mitre_ids"] == ["T1110"] and item["source_type"] == "form" and item["username"] == "alice"


def test_history_filters_search_and_paging():
    h = HistoryStore(tmpdir() / "f.db")
    h.record("alice", {}, fake_result(severity="High", desc="Brute force on web", alert_id="a1"), "paste", now=T0)
    h.record("bob", {}, fake_result(severity="Low", level=3, desc="Backup completed", host="db-02", alert_id="a2"), "paste", now=T0 + timedelta(hours=1))
    h.record("alice", {}, fake_result(severity="Critical", level=13, desc="Ransomware 100% bad_file", alert_id="a3"), "sample", now=T0 + timedelta(hours=2))
    assert h.list(severity="Critical")["total"] == 1
    assert h.list(username="alice")["total"] == 2
    assert h.list(q="backup")["items"][0]["agent_name"] == "db-02"
    assert h.list(q="db-02")["total"] == 1
    assert h.list(q="100%")["total"] == 1            # LIKE wildcards are escaped
    assert h.list(q="%")["total"] == 1 and h.list(q="_")["total"] == 1
    assert [i["alert_id"] for i in h.list()["items"]] == ["a3", "a2", "a1"]   # newest first
    assert len(h.list(limit=2)["items"]) == 2 and len(h.list(limit=2, offset=2)["items"]) == 1
    assert h.list(since="2026-11-18 11:30:00")["total"] == 1


def test_history_delete_permissions():
    h = HistoryStore(tmpdir() / "f.db")
    hid = h.record("alice", {}, fake_result(), now=T0)
    assert not h.delete(hid, "mallory", is_admin=False) and h.count() == 1
    assert h.delete(hid, "alice") and h.count() == 0
    hid = h.record("alice", {}, fake_result(), now=T0)
    assert h.delete(hid, "root-admin", is_admin=True)


# ------------------------------------------------------------------ 03 guided form
def test_form_builds_a_valid_alert():
    r = ap.alert_from_form({"description": "Failed logins", "level": "high", "srcip": "203.0.113.7", "agent_name": "web-01",
                            "user": "root", "mitre": "t1110, T1110.001", "rule_id": "5710", "timestamp": "2026-11-22T10:15"})
    assert r["ok"] and r["source_type"] == "form" and r["needs_confirmation"]
    v = ap.view_of(r["alert"])
    assert v["level"] == 10 and v["severity"] == "High" and v["srcip"] == "203.0.113.7" and v["mitre_ids"] == ["T1110", "T1110.001"]
    assert v["timestamp"].startswith("2026-11-22T10:15:00") and v["mitre_source"] == "entered_by_analyst"
    assert ap.validate_alert(r["alert"])[0]


def test_form_reports_every_bad_field_at_once():
    r = ap.alert_from_form({"srcip": "999.1.1.1", "mitre": "FOO", "level": "20", "timestamp": "yesterday-ish"})
    assert not r["ok"] and set(r["errors"]) == {"description", "srcip", "mitre", "level", "timestamp"}


def test_form_accepts_log_only_and_numeric_level():
    r = ap.alert_from_form({"full_log": "sshd: Failed password for root from 203.0.113.9", "level": "7"})
    assert r["ok"] and ap.view_of(r["alert"])["level"] == 7 and r["alert"]["rule"]["description"].startswith("sshd")
    assert not ap.alert_from_form({"level": "high"})["ok"]            # nothing to analyse


def test_form_blank_level_is_unknown_not_guessed():
    r = ap.alert_from_form({"description": "x"})
    assert r["ok"] and ap.view_of(r["alert"])["level"] is None and any("severity" in w.lower() for w in r["warnings"])


def test_form_templates_are_all_valid():
    for t in ap.FORM_TEMPLATES:
        assert ap.alert_from_form(t["fields"])["ok"], t["key"]


# ------------------------------------------------------------------ 04 weekly report
def _history_for_week():
    h = HistoryStore(tmpdir() / "f.db")
    h.record("alice", {}, fake_result(severity="Critical", level=13, rule="100", desc="Ransomware", alert_id="c1", mitre=("T1486",)), "paste", now=T0)
    h.record("alice", {}, fake_result(alert_id="h1"), "form", now=T0 + timedelta(days=1))
    h.record("bob", {}, fake_result(severity="Low", level=3, rule="200", desc="Backup", alert_id="l1", mitre=(), host="db-02", ip=""), "paste", now=T0 + timedelta(days=1))
    h.record("bob", {}, fake_result(severity="Low", level=3, rule="200", desc="Backup", alert_id="l2", mitre=(), host="db-02", ip=""), "paste", now=T0 + timedelta(days=2))
    h.record("bob", {}, fake_result(alert_id="old"), "paste", now=T0 - timedelta(days=7))            # previous week
    h.record("bob", {}, fake_result(alert_id="out"), "paste", now=T0 + timedelta(days=7))            # next week
    return h


def test_week_is_monday_to_sunday_utc():
    assert rs.monday_of(date(2026, 11, 22)) == date(2026, 11, 16)        # Sunday -> Monday of that week
    s, e = rs.week_window(date(2026, 11, 18))
    assert s == datetime(2026, 11, 16, tzinfo=timezone.utc) and e - s == timedelta(days=7)


def test_weekly_report_counts():
    h = _history_for_week()
    rep = rs.build_weekly_report(h, date(2026, 11, 18), now=datetime(2026, 11, 22, 9, tzinfo=timezone.utc))
    assert rep["week"]["start"] == "2026-11-16" and rep["week"]["end"] == "2026-11-22" and rep["week"]["partial"]
    t = rep["totals"]
    assert t["alerts"] == 4 and t["distinct_alerts"] == 4 and t["analysts"] == 2 and t["high_critical"] == 2
    assert rep["severity"] == {"Low": 2, "Medium": 0, "High": 1, "Critical": 1, "Unknown": 0}
    assert [d["count"] for d in rep["per_day"]] == [0, 0, 1, 2, 1, 0, 0]             # Mon..Sun, Wed/Thu/Fri
    assert rep["top_rules"][0]["rule_id"] == "200" and rep["top_rules"][0]["count"] == 2
    assert {x["id"] for x in rep["top_techniques"]} == {"T1486", "T1110"}
    assert rep["notable"][0]["severity"] == "Critical"                                # sorted by level
    c = rep["comparison"]
    assert c["alerts"] == {"now": 4, "before": 1, "change": 3, "percent": 300}
    assert any("still in progress" in i for i in rep["insights"])


def test_empty_week_and_outputs():
    h = HistoryStore(tmpdir() / "f.db")
    rep = rs.build_weekly_report(h, date(2026, 11, 18), now=datetime(2026, 12, 20, tzinfo=timezone.utc))
    assert rep["totals"]["alerts"] == 0 and rep["insights"] == ["No alerts were analysed in this week."] and not rep["week"]["partial"]
    assert "# SERC weekly security report" in rs.to_markdown(rep)
    h = _history_for_week()
    md = rs.to_markdown(rs.build_weekly_report(h, date(2026, 11, 18), now=datetime(2026, 11, 22, tzinfo=timezone.utc)))
    assert "Ransomware" in md and "| Severity | Alerts |" in md


def test_csv_neutralises_formulas():
    h = HistoryStore(tmpdir() / "f.db")
    h.record("alice", {}, fake_result(desc="=HYPERLINK(\"http://evil\")", alert_id="x"), now=T0)
    out = rs.rows_to_csv(h.between(T0 - timedelta(hours=1), T0 + timedelta(hours=1)))
    assert "'=HYPERLINK" in out and ",=HYPERLINK" not in out and out.splitlines()[0].startswith("time_utc")


def test_finished_weeks_are_saved_once():
    h = _history_for_week()
    out = tmpdir()
    now = datetime(2026, 11, 24, 8, tzinfo=timezone.utc)                       # the week after T0's week
    assert sorted(rs.ensure_saved_reports(h, out, now=now)) == ["weekly-2026-W46.md", "weekly-2026-W47.md"]
    assert rs.ensure_saved_reports(h, out, now=now) == []                       # nothing new the second time
    assert (out / "weekly-2026-W47.md").exists()


# ------------------------------------------------------------------ 02 synchronized dataset
class FakeEmbedder:
    model_name = "fake-embedder"
    def __init__(self): self.embedded = []
    def embed_texts(self, texts, batch_size=32):
        self.embedded += list(texts)
        out = []
        for t in texts:
            seed = int(hashlib.sha1(t.encode()).hexdigest()[:8], 16)
            v = np.random.default_rng(seed).normal(size=1024); out.append((v / np.linalg.norm(v)).tolist())
        return out


def make_store():
    from qdrant_client import QdrantClient
    from backend.services.retrieval_service import RetrievalService
    s = RetrievalService(); s._client = QdrantClient(":memory:"); return s


def rec(cid, text, src="mitre"):
    from backend.services import knowledge_sources as ks
    return ks._new_record(knowledge_source=src, chunk_id=cid, incident_id=cid.split("#")[0], section="description", attack_type=cid,
                          chunk_text=text, source_reference=cid, source_title="t", data_origin="official")


class Source:
    """A pretend data_sources folder: tests change `.records` to simulate an update."""
    def __init__(self, records): self.records = records
    def __call__(self, data_dir, quick=False, include_rev2=False):
        out = {"mitre": [], "nist": [], "incident_response": []}
        for r in self.records: out[r["knowledge_source"]].append(r)
        return out


def make_sync(source, store=None, emb=None):
    d = tmpdir(); (d / "enterprise-attack.json").write_text("{}")
    return DatasetSync(d, d / "manifest.json", store or make_store(), emb or FakeEmbedder(), loader=source), d


def base_records():
    return [rec("T1110#description", "Brute force guesses passwords."), rec("T1078#description", "Valid accounts abused."),
            rec("CSF#GV.OC-01", "Organisational context is understood.", "nist"), rec("IRM-3#000", "Review authentication logs.", "incident_response")]


def test_first_sync_builds_everything_then_second_does_nothing():
    src, emb = Source(base_records()), FakeEmbedder()
    sync, _ = make_sync(src, emb=emb)
    assert sync.status()["state"] == "never_synced"
    r = sync.sync()
    assert r["to_add"] == 4 and r["added_or_updated"] == 4 and r["failed"] == 0 and len(emb.embedded) == 4
    assert sync.status()["state"] == "up_to_date" and sync.status()["stored"] == 4
    r2 = sync.sync()
    assert r2["to_add"] == r2["to_update"] == r2["stale"] == 0 and r2["unchanged"] == 4 and len(emb.embedded) == 4   # nothing re-embedded


def test_changed_new_and_stale_passages_are_detected():
    src, emb = Source(base_records() + [rec("IRM-3#001", "Preserve logs before changes.", "incident_response")]), FakeEmbedder()
    sync, _ = make_sync(src, emb=emb); sync.sync(); before = len(emb.embedded)
    src.records = [rec("IRM-3#001", "Preserve logs before changes.", "incident_response"),
                   rec("T1110#description", "Brute force guesses passwords. UPDATED wording."),      # changed
                   rec("T1078#description", "Valid accounts abused."),                                  # same
                   rec("T1486#description", "Data encrypted for impact."),                              # new
                   rec("CSF#GV.OC-01", "Organisational context is understood.", "nist"),
                   rec("IRM-3#000", "Review authentication logs.", "incident_response")]
    dry = sync.sync(dry_run=True)
    assert (dry["to_add"], dry["to_update"], dry["stale"], dry["unchanged"]) == (1, 1, 0, 4) and len(emb.embedded) == before
    r = sync.sync()
    assert r["added_or_updated"] == 2 and len(emb.embedded) == before + 2 and sync.status()["stored"] == 6
    src.records = [x for x in src.records if x["chunk_id"] != "IRM-3#000"]   # one passage disappears from the sources
    assert sync.sync(dry_run=True)["stale"] == 1
    kept = sync.sync(); assert kept["stale_left"] == 1 and sync.status()["stored"] == 6       # stale kept unless asked
    gone = sync.sync(prune=True); assert gone["removed"] == 1 and sync.status()["stored"] == 5
    assert sync.sync()["stale"] == 0 and sync.status()["state"] == "up_to_date"


def test_a_source_that_parses_to_nothing_never_wipes_the_database():
    src = Source(base_records())
    sync, _ = make_sync(src); sync.sync()
    src.records = [r for r in src.records if r["knowledge_source"] != "mitre"]   # e.g. enterprise-attack.json missing
    p = sync.sync(prune=True)
    assert p["removed"] == 0 and sync.status()["stored"] == 4 and any("mitre" in n for n in p["notes"])


def test_existing_database_without_manifest_is_adopted_not_reembedded():
    src, emb = Source(base_records()), FakeEmbedder()
    store = make_store(); first, _ = make_sync(src, store, emb); first.sync()
    n = len(emb.embedded)
    sync2, d2 = make_sync(src, store, emb)                          # same database, but no manifest (older ingestion)
    assert sync2.status()["state"] == "untracked"
    r = sync2.sync()
    assert r["adopted"] == 4 and len(emb.embedded) == n and sync2.status()["state"] == "up_to_date"


def test_status_notices_source_file_changes_and_database_drift():
    src = Source(base_records())
    sync, d = make_sync(src); sync.sync()
    assert sync.status()["state"] == "up_to_date"
    (d / "enterprise-attack.json").write_text('{"changed": true}')
    st = sync.status()
    assert st["state"] == "changes_pending" and any(f["state"] == "changed" for f in st["files"])
    sync.sync(); assert sync.status()["state"] == "up_to_date"
    sync.store.delete_chunks(["T1110#description"])                  # someone damages the database
    st = sync.status()
    assert st["state"] == "changes_pending" and any("holds 3" in i for i in st["issues"])
    assert sync.sync()["to_add"] == 1 and sync.status()["state"] == "up_to_date"


def test_embedding_model_change_reembeds_everything():
    src, emb = Source(base_records()), FakeEmbedder()
    sync, _ = make_sync(src, emb=emb); sync.sync(); n = len(emb.embedded)
    emb.model_name = "another-model"
    assert sync.status()["state"] == "changes_pending"
    r = sync.sync(); assert r["model_changed"] and len(emb.embedded) == n + 4


def test_failed_batch_is_retried_next_time():
    src, emb = Source(base_records()), FakeEmbedder()
    sync, _ = make_sync(src, emb=emb)
    real = emb.embed_texts
    emb.embed_texts = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("model crashed"))
    r = sync.sync(); assert r["failed"] == 4 and sync.status()["stored"] == 0
    emb.embed_texts = real
    assert sync.sync()["added_or_updated"] == 4


def test_background_job_reports_progress_and_blocks_a_second_start():
    import time
    sync, _ = make_sync(Source(base_records()))
    sync.start_job()
    for _ in range(100):
        if sync.job_status()["state"] != "running": break
        time.sleep(0.05)
    job = sync.job_status()
    assert job["state"] == "done" and job["result"]["added_or_updated"] == 4
