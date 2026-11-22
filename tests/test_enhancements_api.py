"""End-to-end API tests for the four enhancements, using a throwaway database folder and a fake knowledge base.
Run from the project root, preferably on its own:   python -m pytest tests/test_enhancements_api.py -v
"""
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp())
for key, val in {
    "FEEDBACK_DB_PATH": str(_TMP / "feedback.db"), "AUTH_DB_PATH": str(_TMP / "auth.db"), "SECRET_KEY": "x" * 32,
    "ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "Admin-pass-123!", "QDRANT_PATH": str(_TMP / "qdrant"),
    "DATASET_MANIFEST_PATH": str(_TMP / "manifest.json"), "REPORTS_DIR": str(_TMP / "reports"),
    "MOCK_LLM_MODE": "true", "OPENAI_API_KEY": "", "QDRANT_URL": "",
}.items():
    os.environ[key] = val

from backend.config import settings  # noqa: E402

pytestmark = pytest.mark.skipif(settings.auth_db_file.parent != _TMP,
                                reason="settings were already loaded by another test module; run this file on its own")

from fastapi.testclient import TestClient  # noqa: E402

from backend.main import app  # noqa: E402
from backend.routes import alerts as routes  # noqa: E402
from backend.routes.auth import auth_service  # noqa: E402
from tests.fake_kb import FakeRetriever, build_records  # noqa: E402
from tests.test_enhancements import FakeEmbedder, Source, base_records  # noqa: E402


@pytest.fixture(scope="module")
def client():
    routes.retriever = FakeRetriever(build_records())
    routes.dataset.embedder = FakeEmbedder()
    routes.dataset.loader = Source(base_records())
    with TestClient(app) as c:                 # runs startup: creates the admin user
        yield c


def login(client, user="admin", pw="Admin-pass-123!"):
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text


SSH = {"description": "Multiple failed SSH logins", "level": "high", "agent_name": "web-01", "srcip": "203.0.113.50",
       "user": "root", "mitre": "T1110", "full_log": "sshd: Failed password for invalid user admin from 203.0.113.50"}


def test_everything_needs_a_session(client):
    client.cookies.clear()
    for path in ("/api/history", "/api/reports/weekly", "/api/dataset/status", "/api/alerts/form-options"):
        assert client.get(path).status_code == 401, path


def test_form_to_history_to_report_flow(client):
    login(client)
    opts = client.get("/api/alerts/form-options").json()
    assert {t["key"] for t in opts["templates"]} >= {"ssh_bruteforce", "malware"} and "T1110" in opts["techniques"]

    bad = client.post("/api/alerts/from-form", json={"srcip": "nope"}).json()
    assert bad["ok"] is False and "srcip" in bad["errors"] and "description" in bad["errors"]

    form = client.post("/api/alerts/from-form", json=SSH).json()
    assert form["ok"] and form["source_type"] == "form"

    res = client.post("/api/alerts/analyze", json={"alert": form["alert"], "source_type": "form"})
    assert res.status_code == 200, res.text
    out = res.json()
    assert out["ok"] and isinstance(out["history_id"], int)
    assert out["alert"]["severity"] == "High" and out["alert"]["mitre_ids"] == ["T1110"]

    page = client.get("/api/history").json()
    assert page["total"] == 1 and page["me"] == "admin"
    row = page["items"][0]
    assert row["id"] == out["history_id"] and row["source_type"] == "form" and row["username"] == "admin"

    full = client.get(f"/api/history/{row['id']}").json()
    assert full["alert"]["rule"]["description"] == SSH["description"]
    assert full["result"]["summary"]["headline"] == out["summary"]["headline"]       # reopened without re-analysis

    assert client.get("/api/history?q=web-01&severity=High&days=7&mine=true").json()["total"] == 1
    assert client.get("/api/history?severity=Low").json()["total"] == 0

    rep = client.get("/api/reports/weekly").json()
    assert rep["totals"]["alerts"] == 1 and rep["week"]["partial"]
    assert rep["top_techniques"][0]["id"] == "T1110" and rep["notable"][0]["history_id"] == row["id"]
    weeks = client.get("/api/reports/weeks").json()
    assert weeks[0]["alerts"] == 1 and len(weeks) == 8
    md = client.get("/api/reports/weekly.md")
    assert md.status_code == 200 and "SERC weekly security report" in md.text and "attachment" in md.headers["content-disposition"]
    assert "Multiple failed SSH logins" in client.get("/api/reports/weekly.csv").text
    assert "web-01" in client.get("/api/history/export.csv").text
    assert client.get("/api/reports/weekly?week_start=banana").status_code == 422
    assert client.get("/api/reports/weekly?week_start=2020-01-06").json()["totals"]["alerts"] == 0


def test_analysis_still_works_if_history_saving_fails(client, monkeypatch):
    login(client)
    monkeypatch.setattr(routes.history, "record", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full")))
    form = client.post("/api/alerts/from-form", json={"description": "Port scan", "level": "medium"}).json()
    res = client.post("/api/alerts/analyze", json={"alert": form["alert"]})
    assert res.status_code == 200 and res.json()["history_id"] is None


def test_delete_permissions(client):
    login(client)
    auth_service.create_user("alice", "Alice-pass-123!")
    hid = client.get("/api/history").json()["items"][0]["id"]       # created by admin
    client.cookies.clear(); login(client, "alice", "Alice-pass-123!")
    assert client.get("/api/history").json()["total"] >= 1           # team history is visible
    assert client.get("/api/history?mine=true").json()["total"] == 0
    assert client.delete(f"/api/history/{hid}").status_code == 404   # but not deletable by another analyst
    form = client.post("/api/alerts/from-form", json={"description": "Alice's alert", "level": "low"}).json()
    mine = client.post("/api/alerts/analyze", json={"alert": form["alert"], "source_type": "form"}).json()["history_id"]
    assert client.delete(f"/api/history/{mine}").status_code == 200
    assert client.get(f"/api/history/{mine}").status_code == 404
    client.cookies.clear(); login(client)
    assert client.delete(f"/api/history/{hid}").status_code == 200   # admin may delete any entry


def test_dataset_status_sync_and_permissions(client):
    login(client)
    st = client.get("/api/dataset/status").json()
    assert st["state"] == "never_synced" and st["stored"] == 0 and any(f["name"] == "enterprise-attack.json" for f in st["files"])

    preview = client.post("/api/dataset/preview").json()
    assert preview["dry_run"] and preview["to_add"] == 4 and client.get("/api/dataset/status").json()["stored"] == 0

    client.cookies.clear(); login(client, "alice", "Alice-pass-123!")
    assert client.post("/api/dataset/sync", json={}).status_code == 403
    assert client.post("/api/dataset/preview").status_code == 403
    assert client.get("/api/dataset/status").status_code == 200      # everybody may look

    client.cookies.clear(); login(client)
    assert client.post("/api/dataset/sync", json={"prune": False}).status_code == 200
    import time
    for _ in range(200):
        job = client.get("/api/dataset/sync").json()
        if job["state"] != "running":
            break
        time.sleep(0.05)
    assert job["state"] == "done" and job["result"]["added_or_updated"] == 4
    st = client.get("/api/dataset/status").json()
    assert st["stored"] == 4 and st["recorded"] == 4 and st["last_sync"]
    assert client.get("/api/health").json()["vectors"] == 4          # the health pill sees the new passages


def test_static_pages_are_served(client):
    client.cookies.clear(); login(client)
    html = client.get("/").text
    for needle in ('id="viewnav"', 'id="g-description"', 'id="view-history"', 'id="view-report"', 'id="view-dataset"', "enhancements.js"):
        assert needle in html, needle
    assert client.get("/enhancements.js").status_code == 200
