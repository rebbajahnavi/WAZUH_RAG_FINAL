"""REST API for SERC. Thin layer: the logic lives in backend/services/."""
from __future__ import annotations

import json
import logging
import threading
from functools import lru_cache
from typing import Any, Dict, List, Optional

from datetime import date, timedelta

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from backend.config import settings
from backend.routes.auth import require_user
from backend.services import alert_parser as ap
from backend.services import analysis_service as an
from backend.services import report_service as rs
from backend.services.dataset_sync import DatasetSync
from backend.services.embedding_service import embedding_service
from backend.services.feedback_service import FeedbackService
from backend.services.history_service import HistoryStore, fmt_time, utc_now
from backend.services.llm_client import LLMClient
from backend.services.retrieval_service import retrieval_service

logger = logging.getLogger("serc.routes")
router = APIRouter(prefix="/api")

llm = LLMClient(settings)
feedback = FeedbackService(settings.feedback_db_file)
history = HistoryStore(settings.feedback_db_file)

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_IMAGE_BYTES = 5 * 1024 * 1024
TEXT_EXT = {".json", ".log", ".txt", ".csv", ".ndjson", ".jsonl", ""}
IMAGE_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}


_kb_lock = threading.Lock()  # embedded Qdrant and the embedding model are not built for parallel requests


class RetrieverAdapter:
    def search(self, query: str, top_k: int = 5):
        with _kb_lock:
            return retrieval_service.search_evidence(query, top_k=top_k)

    def lookup_technique(self, tid: str):
        with _kb_lock:
            return retrieval_service.lookup_technique(tid)


retriever = RetrieverAdapter()

dataset = DatasetSync(settings.dataset_data_dir, settings.dataset_manifest_file, retrieval_service, embedding_service,
                      scope=settings.dataset_scope, include_rev2=settings.dataset_include_rev2, lock=_kb_lock)


@lru_cache(maxsize=1)
def _samples() -> List[Dict[str, Any]]:
    path = settings.sample_alerts_file
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ status
@router.get("/health")
def health():
    with _kb_lock:
        stats = retrieval_service.get_stats()
    return {
        "status": "ok",
        "vectors": stats.get("total_vectors", 0),
        "collection_error": stats.get("error"),
        "mode": "live" if llm.text_live else "offline",
        "vision_available": llm.vision_live,
        "embedding_model": settings.embedding_model_name,
        "llm_model": settings.openai_model if llm.text_live else "",
    }


# ------------------------------------------------------------------ samples
@router.get("/alerts/samples")
def list_samples():
    rows = []
    for a in _samples():
        v = ap.view_of(a)
        rows.append({"id": v["alert_id"], "rule_id": v["rule_id"], "level": v["level"], "severity": v["severity"],
                     "agent": v["agent_name"], "description": v["description"],
                     "label": f"[{v['severity']}] {v['description']} ({v['agent_name']})"})
    return rows


@router.get("/alerts/samples/{alert_id}")
def get_sample(alert_id: str):
    for a in _samples():
        if ap.view_of(a)["alert_id"] == alert_id:
            return a
    raise HTTPException(404, "Sample alert not found")


# ------------------------------------------------------------------ input handling
@router.post("/alerts/ingest")
def ingest(text: Optional[str] = Form(None), file: Optional[UploadFile] = File(None)):
    """Accepts pasted text or an uploaded file (json, log, txt, csv, png, jpg) and returns a normalised alert."""
    if file is not None and file.filename:
        name = file.filename.lower()
        ext = name[name.rfind("."):] if "." in name else ""
        if ext in IMAGE_MIME:
            data = file.file.read(MAX_IMAGE_BYTES + 1)
            if len(data) > MAX_IMAGE_BYTES:
                return {"ok": False, "message": "The image is larger than 5 MB. Please use a smaller screenshot."}
            if not llm.vision_live:
                return {"ok": False, "code": "vision_unavailable",
                        "message": "Reading images needs live mode (an OpenAI key in backend/.env), which is not set up here. "
                                   "Please paste the alert text or upload the JSON or log file instead."}
            try:
                alert = llm.read_alert_image(data, IMAGE_MIME[ext])
            except Exception as exc:
                logger.warning("Image reading failed: %s", exc)
                return {"ok": False, "message": "The image could not be read. Try a clearer screenshot, or paste the text instead."}
            return {"ok": True, "source_type": "image", "alert": alert, "extracted": ap._extracted_fields(alert),
                    "warnings": ["Details were read from an image and can contain mistakes. Please check them before analysing."],
                    "needs_confirmation": True}
        if ext not in TEXT_EXT:
            return {"ok": False, "message": f"'{ext}' files are not supported. Use .json, .log, .txt, .csv, .png or .jpg."}
        raw = file.file.read(MAX_TEXT_BYTES + 1)
        if len(raw) > MAX_TEXT_BYTES:
            return {"ok": False, "message": "The file is larger than 2 MB. Please upload a smaller file."}
        return ap.parse_input(raw.decode("utf-8", errors="replace"), filename=file.filename)
    return ap.parse_input(text or "")


# ------------------------------------------------------------------ guided form (enhancement 03)
class FormRequest(BaseModel):
    description: str = ""
    level: str = ""
    agent_name: str = ""
    srcip: str = ""
    user: str = ""
    rule_id: str = ""
    mitre: str = ""
    timestamp: str = ""
    full_log: str = ""


@router.get("/alerts/form-options")
def form_options():
    """What the guided form offers: severity choices, starting templates and common ATT&CK techniques."""
    from backend.services.knowledge_sources import QUICK_TECHNIQUES
    return {"severities": [{"value": k, "label": k.capitalize(), "level": v} for k, v in ap.FORM_SEVERITY_LEVELS.items()],
            "templates": ap.FORM_TEMPLATES, "techniques": sorted(QUICK_TECHNIQUES)}


@router.post("/alerts/from-form")
def from_form(req: FormRequest):
    """Turns the guided form into a normalised alert (same result shape as /alerts/ingest). Field problems come back per field."""
    return ap.alert_from_form(req.model_dump())


# ------------------------------------------------------------------ analysis
class AnalyzeRequest(BaseModel):
    alert: Dict[str, Any]
    source_type: str = ""      # how the alert was supplied (paste, form, sample ...), kept in the history


@router.post("/alerts/analyze")
def analyze(req: AnalyzeRequest, user: Dict[str, Any] = Depends(require_user)):
    result = an.analyze_alert(req.alert, retriever, llm=llm, top_k=settings.top_k_retrieval)
    if not result.get("ok"):
        raise HTTPException(422, "; ".join(result.get("errors", ["Invalid alert"])))
    try:  # saving to the history must never stop the analyst from seeing the analysis
        result["history_id"] = history.record(user["username"], req.alert, result, req.source_type)
    except Exception as exc:
        logger.warning("Could not save to the alert history: %s", exc)
        result["history_id"] = None
    return result


@router.post("/alerts/compare")
def compare(req: AnalyzeRequest):
    """Live mode only: the same alert answered with retrieved evidence and without it (the paper's missing baseline)."""
    return an.compare_rag(req.alert, retriever, llm, top_k=settings.top_k_retrieval)


class ChatRequest(BaseModel):
    alert: Optional[Dict[str, Any]] = None
    question: str


@router.post("/alerts/chat")
def chat(req: ChatRequest):
    return an.answer_question(req.alert or {}, req.question, retriever, llm=llm)


# ------------------------------------------------------------------ feedback
class FeedbackRequest(BaseModel):
    alert_id: str
    claim_id: str
    decision: str
    claim_text: str = ""
    note: str = ""


@router.post("/feedback")
def save_feedback(req: FeedbackRequest):
    try:
        return feedback.save(req.alert_id, req.claim_id, req.decision, req.claim_text, req.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/feedback/{alert_id}")
def get_feedback(alert_id: str):
    return feedback.list_for_alert(alert_id)


# ------------------------------------------------------------------ alert history (enhancement 01)
def _is_admin(user: Dict[str, Any]) -> bool:
    return user.get("role") == "admin"


def _since(days: int) -> str:
    return fmt_time(utc_now() - timedelta(days=days)) if days and days > 0 else ""


@router.get("/history")
def list_history(q: str = "", severity: str = "", days: int = Query(0, ge=0, le=3650), mine: bool = False,
                 limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0), user: Dict[str, Any] = Depends(require_user)):
    """Previously analysed alerts, newest first. The whole team's history is shown unless ``mine`` is set."""
    out = history.list(user["username"] if mine else None, q, severity, _since(days), limit, offset)
    out["me"] = user["username"]
    return out


@router.get("/history/export.csv")
def export_history(q: str = "", severity: str = "", days: int = Query(0, ge=0, le=3650), mine: bool = False,
                   user: Dict[str, Any] = Depends(require_user)):
    page = history.list(user["username"] if mine else None, q, severity, _since(days), 200, 0)
    rows, total = page["items"], page["total"]
    while len(rows) < total and len(rows) < 5000:
        rows += history.list(user["username"] if mine else None, q, severity, _since(days), 200, len(rows))["items"]
    return Response(rs.rows_to_csv(rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="serc-alert-history.csv"'})


@router.get("/history/{history_id}")
def get_history(history_id: int):
    item = history.get(history_id)
    if not item:
        raise HTTPException(404, "That history entry no longer exists.")
    return item


@router.delete("/history/{history_id}")
def delete_history(history_id: int, user: Dict[str, Any] = Depends(require_user)):
    if not history.delete(history_id, user["username"], _is_admin(user)):
        raise HTTPException(404, "Not found, or it belongs to another analyst.")
    return {"ok": True}


# ------------------------------------------------------------------ weekly reports (enhancement 04)
def _week_param(week_start: str) -> Optional[date]:
    if not week_start:
        return None
    try:
        return date.fromisoformat(week_start)
    except ValueError:
        raise HTTPException(422, "week_start must look like 2026-11-16.")


@router.get("/reports/weeks")
def report_weeks():
    return rs.available_weeks(history)


@router.get("/reports/weekly")
def weekly_report(week_start: str = ""):
    return rs.build_weekly_report(history, _week_param(week_start))


@router.get("/reports/weekly.md")
def weekly_report_markdown(week_start: str = ""):
    rep = rs.build_weekly_report(history, _week_param(week_start))
    return Response(rs.to_markdown(rep), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="serc-weekly-{rep["week"]["start"]}.md"'})


@router.get("/reports/weekly.csv")
def weekly_report_csv(week_start: str = ""):
    start, end = rs.week_window(_week_param(week_start) or utc_now().date())
    return Response(rs.rows_to_csv(history.between(start, end)), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="serc-alerts-{start.date().isoformat()}.csv"'})


# ------------------------------------------------------------------ synchronized dataset (enhancement 02)
@router.get("/dataset/status")
def dataset_status():
    """Cheap check (no parsing): are the source files, the manifest and the vector database in step?"""
    return dataset.status()


class SyncRequest(BaseModel):
    prune: bool = False


@router.post("/dataset/sync")
def dataset_sync(req: SyncRequest, user: Dict[str, Any] = Depends(require_user)):
    """Starts a background synchronisation. Admins only, because it changes the shared knowledge base."""
    if not _is_admin(user):
        raise HTTPException(403, "Only an administrator can synchronise the knowledge base.")
    return dataset.start_job(prune=req.prune)


@router.post("/dataset/preview")
def dataset_preview(user: Dict[str, Any] = Depends(require_user)):
    """Reads the sources and says what a sync would add, update or remove. Changes nothing."""
    if not _is_admin(user):
        raise HTTPException(403, "Only an administrator can preview a synchronisation.")
    if dataset.job_status().get("state") == "running":
        raise HTTPException(409, "A synchronisation is already running.")
    return dataset.sync(dry_run=True)


@router.get("/dataset/sync")
def dataset_sync_progress():
    return dataset.job_status()
