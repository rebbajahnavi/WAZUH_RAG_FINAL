"""
Synchronise the knowledge base with the files in data_sources/ (only new or changed passages are embedded).

Usage (project root, server STOPPED, because the embedded Qdrant folder allows one program at a time):
    python backend/scripts/sync_dataset.py --dry-run     # show what would change, change nothing
    python backend/scripts/sync_dataset.py               # add new and changed passages
    python backend/scripts/sync_dataset.py --prune       # also remove passages that no source produces any more
With the server running, use the "Knowledge base" page instead (administrators only).
"""
import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import settings  # noqa: E402
from backend.services.dataset_sync import DatasetSync  # noqa: E402
from backend.services.embedding_service import embedding_service  # noqa: E402
from backend.services.retrieval_service import retrieval_service  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Synchronise SERC's knowledge base with data_sources/")
    ap.add_argument("--dry-run", action="store_true", help="Report what would change; write nothing")
    ap.add_argument("--prune", action="store_true", help="Remove stored passages that no source produces any more")
    ap.add_argument("--full", action="store_true", help="Use the full ATT&CK set instead of DATASET_SCOPE from .env")
    args = ap.parse_args()
    scope = "full" if args.full else settings.dataset_scope
    sync = DatasetSync(settings.dataset_data_dir, settings.dataset_manifest_file, retrieval_service, embedding_service,
                       scope=scope, include_rev2=settings.dataset_include_rev2)
    try:
        result = sync.sync(prune=args.prune, dry_run=args.dry_run,
                           progress=lambda phase, done, total: print(f"  {phase}" + (f": {done}/{total}" if total else ""), flush=True))
        print("\nRESULT" + (" (dry run, nothing changed)" if args.dry_run else ""))
        for k, v in result.items():
            print(f"  {k}: {v}")
    finally:
        retrieval_service.close()
