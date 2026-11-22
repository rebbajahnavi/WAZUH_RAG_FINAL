"""
Main application entry point for SERC (Security Event Response Copilot).
Launches FastAPI with CORS, API routes, and serves the clean light-themed UI.
"""
import sys
import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure project root is in sys.path when executed directly as `python backend/main.py`
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse

from backend.config import settings
from backend.routes.alerts import history as alert_history, router as alerts_router
from backend.routes.auth import auth_service, current_user_or_none, require_user, router as auth_router
from backend.services import report_service
from backend.services.retrieval_service import retrieval_service

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("serc.main")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def _weekly_report_saver(stop: threading.Event) -> None:
    """Saves a Markdown report for every finished week (backend/data/reports). Checks at start and then hourly."""
    while not stop.is_set():
        try:
            for name in report_service.ensure_saved_reports(alert_history, settings.reports_path):
                logger.info("Saved weekly report %s", name)
        except Exception as exc:
            logger.warning("Weekly report saving skipped: %s", exc)
        stop.wait(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler: checks system health and vector store on startup."""
    logger.info("Initializing SERC (Security Event Response Copilot)...")
    logger.info(f"Environment: {settings.environment} | Mock Mode: {settings.is_mock}")
    try:
        generated = auth_service.ensure_default_admin(settings.admin_username, settings.admin_password)
        if generated:
            logger.warning("=" * 64)
            logger.warning("First start: created user '%s' with the one-time password:  %s", settings.admin_username, generated)
            logger.warning("Sign in, then change it (or set ADMIN_PASSWORD in backend/.env before the first start).")
            logger.warning("=" * 64)
        elif auth_service.user_count() == 0:
            logger.error("No users exist and none could be created. Run: python backend/scripts/create_user.py")
    except Exception as e:
        logger.error(f"Could not prepare the user database: {e}")
    try:
        stats = retrieval_service.get_stats()
        logger.info(f"Vector Store Status: {stats.get('total_vectors', 0)} vectors available in collection '{settings.qdrant_collection}'")
    except Exception as e:
        logger.warning(f"Vector store initial check warning: {e}")
    stop = threading.Event()
    threading.Thread(target=_weekly_report_saver, args=(stop,), name="serc-weekly-reports", daemon=True).start()
    yield
    stop.set()
    logger.info("Shutting down SERC.")


app = FastAPI(
    title="SERC — Security Event Response Copilot",
    description="Wazuh Security Event Response Copilot powered by RAG and Evidence-Backed Validation.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins() or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Never let the browser reuse stale copies of the UI files (stale CSS/JS broke the theme toggle)
@app.middleware("http")
async def no_cache_frontend(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if not path.startswith("/api") and (path == "/" or path.endswith((".html", ".css", ".js"))):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response

# Include API endpoints
app.include_router(auth_router)  # /api/auth/*  (login is public)
app.include_router(alerts_router, dependencies=[Depends(require_user)])  # everything else needs a signed-in user

# Mount frontend files if directory exists
if FRONTEND_DIR.exists():
    # Serve index.html at root
    @app.get("/", include_in_schema=False)
    async def serve_index(request: Request):
        if not current_user_or_none(request):
            return RedirectResponse("/login.html", status_code=302)
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "Frontend index.html not found"}

    # Mount static assets (style.css, script.js)
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    # Also mount root static so relative paths like "style.css" and "script.js" resolve directly
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting SERC server on http://{settings.host}:{settings.port}")
    uvicorn.run("backend.main:app", host=settings.host, port=settings.port, reload=False, app_dir=str(PROJECT_ROOT))
