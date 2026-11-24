"""Rewrite the sync manifest so it matches the passages ALREADY stored in Qdrant, using the current
embedding model. Nothing is embedded and no quota is used.

Use it when the Knowledge base page says "The embedding model changed since the last sync" but the
stored vectors were in fact made with the current model. Run from the project root:

    python backend/scripts/refresh_manifest.py

It refuses to write the manifest unless every passage the sources produce is really stored.
Afterwards commit backend/data/dataset_manifest.json and push, so deploys start with the right record.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.config import settings  # noqa: E402
from backend.services.embedding_service import embedding_service  # noqa: E402
from backend.services.retrieval_service import retrieval_service  # noqa: E402
from backend.services.dataset_sync import DatasetSync  # noqa: E402
from backend.services.knowledge_sources import ALL_SOURCES, load_all  # noqa: E402  (same loader the ingest uses)

data_dir = Path(settings.dataset_data_dir)
sources = load_all(data_dir, quick=True, include_rev2=False)
parsed = {r["chunk_id"] for name in ALL_SOURCES for r in sources.get(name, [])}
stored = set(retrieval_service.list_stored_chunks().keys())
missing = parsed - stored
print(f"model: {embedding_service.model_name} ({embedding_service.dimension} dims)")
print(f"passages from source files: {len(parsed)} | stored in Qdrant: {len(stored)} | missing: {len(missing)}")
if missing or not parsed:
    sys.exit("NOT written: some passages are not stored yet. Finish the ingest first (python backend/scripts/ingest_sources.py --quick).")
DatasetSync(data_dir, settings.dataset_manifest_file, retrieval_service, embedding_service,
            scope="quick", include_rev2=False).record_after_ingest(sources, True)
print("Manifest written:", settings.dataset_manifest_file)
retrieval_service.close()
