"""Create the payload indexes Qdrant Cloud needs, on the collection that already exists.
No re-ingestion and no embedding model needed. Run from the project root:
    python backend/scripts/create_indexes.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from qdrant_client.models import PayloadSchemaType  # noqa: E402
from backend.config import settings  # noqa: E402
from backend.services.retrieval_service import retrieval_service  # noqa: E402

print("Qdrant:", settings.qdrant_url or settings.qdrant_path, "| collection:", settings.qdrant_collection)
cl = retrieval_service.client
if not cl.collection_exists(settings.qdrant_collection):
    sys.exit("Collection not found. Check QDRANT_URL / QDRANT_COLLECTION in backend/.env.")
for field in retrieval_service.INDEXED_FIELDS:
    try:
        cl.create_payload_index(settings.qdrant_collection, field, PayloadSchemaType.KEYWORD)
        print("created index:", field)
    except Exception as exc:
        print("index", field, "->", str(exc)[:120])
print("points in collection:", cl.count(settings.qdrant_collection).count)