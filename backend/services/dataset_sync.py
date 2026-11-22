"""Synchronized dataset for SERC (enhancement 02).

Keeps the vector knowledge base (Qdrant) consistent with the source files in ``data_sources/``:

* **New or changed passages** are embedded and stored.
* **Stale passages** (no longer produced by the sources, for example a withdrawn ATT&CK technique) are reported
  and, when the analyst asks for it, removed.
* **Unchanged passages are never embedded again**, so a re-sync after a small update takes seconds instead of
  the ~30 minutes of a full build.

How it decides, in plain terms:

1. Parse the sources with the same parsers the ingestion script uses.
2. Give every passage a fingerprint (SHA-1 of all its fields). The fingerprints of the last sync are kept in
   ``dataset_manifest.json`` next to the database.
3. Compare with what is *actually stored* in Qdrant (not only with the manifest), so a manifest that was lost
   or a database that was edited by hand cannot hide a problem.

``status()`` is cheap (file sizes, modification times and hashes only, no parsing) and is safe to call often.
``plan()`` and ``sync()`` parse everything and can take a while for the full ATT&CK file.

A knowledge base built with the older ``ingest_sources.py`` has no manifest. The first sync adopts the stored
passages as they are (nothing is re-embedded) and records their fingerprints from then on. Changes made to a
source before that first sync cannot be detected for passages that already existed; use ``--recreate`` once
if you are unsure.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.services import knowledge_sources as ks

logger = logging.getLogger("serc.dataset_sync")

MANIFEST_VERSION = 1


def record_hash(rec: Dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(rec, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")).hexdigest()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())


class DatasetSync:
    def __init__(self, data_dir: Path, manifest_path: Path, store, embedder, scope: str = "quick", include_rev2: bool = False,
                 loader: Callable[..., Dict[str, List[Dict]]] = ks.load_all, lock: Optional[Any] = None, batch_size: int = 32):
        """``store`` is a RetrievalService (or a stand-in with the same methods); ``embedder`` an EmbeddingService."""
        self.data_dir = Path(data_dir)
        self.manifest_path = Path(manifest_path)
        self.store, self.embedder = store, embedder
        self.scope = "full" if str(scope).lower() == "full" else "quick"
        self.include_rev2 = bool(include_rev2)
        self.loader = loader
        self.lock = lock if lock is not None else contextlib.nullcontext()
        self.batch_size = batch_size
        self._job: Dict[str, Any] = {"state": "idle"}
        self._job_lock = threading.Lock()

    # ------------------------------------------------------------------ manifest
    def load_manifest(self) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return data if data.get("version") == MANIFEST_VERSION else None
        except (OSError, ValueError):
            return None

    def _write_manifest(self, manifest: Dict[str, Any]) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.manifest_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.manifest_path)  # atomic: a crash never leaves a half-written manifest

    # ------------------------------------------------------------------ source files
    def source_files(self) -> List[Dict[str, Any]]:
        """The files the parsers read, with the knowledge source each feeds."""
        d, out = self.data_dir, []
        def add(path: Path, source: str):
            out.append({"path": path, "name": path.relative_to(d).as_posix(), "source": source})
        if (d / "enterprise-attack.json").exists():
            add(d / "enterprise-attack.json", ks.SRC_MITRE)
        cands = list(d.glob("csf2*.xlsx")) + list(d.glob("*csf*.xlsx"))
        if cands:
            add(cands[0], ks.SRC_NIST)
        if d.exists():
            for irm in (p for p in d.iterdir() if p.is_dir() and p.name.lower().startswith("irm")):
                for pdf in sorted(irm.rglob("*.pdf")):
                    add(pdf, ks.SRC_IR)
            for rev in ["r3"] + (["r2"] if self.include_rev2 else []):
                for pdf in sorted(d.glob("*.pdf")):
                    if f"800-61{rev}" in pdf.name.lower():
                        add(pdf, ks.SRC_IR)
        return out

    def _fingerprints(self, previous: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """size + modification time, and a content hash only when the cheap check says the file may have changed."""
        out: Dict[str, Dict[str, Any]] = {}
        for f in self.source_files():
            st = f["path"].stat()
            prev = previous.get(f["name"])
            if prev and prev.get("size") == st.st_size and prev.get("mtime_ns") == st.st_mtime_ns and prev.get("sha256"):
                digest = prev["sha256"]
            else:
                digest = _sha256(f["path"])
            out[f["name"]] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "sha256": digest, "source": f["source"]}
        return out

    # ------------------------------------------------------------------ status (cheap)
    def status(self) -> Dict[str, Any]:
        manifest = self.load_manifest()
        with self.lock:
            stats = self.store.get_stats()
        stored = int(stats.get("total_vectors", 0))
        prev_files = (manifest or {}).get("files", {})
        files: List[Dict[str, Any]] = []
        try:
            current = self._fingerprints(prev_files)
        except OSError as exc:
            return {"state": "error", "message": f"Could not read the source files: {exc}", "stored": stored, "job": self.job_status()}
        for name, fp in current.items():
            old = prev_files.get(name)
            state = "new" if manifest and not old else "changed" if old and old.get("sha256") != fp["sha256"] else "unchanged" if old else "unknown"
            files.append({"name": name, "source": fp["source"], "size": fp["size"], "modified": time.strftime("%Y-%m-%d %H:%M", time.gmtime(fp["mtime_ns"] / 1e9)), "state": state})
        missing = [n for n in prev_files if n not in current]
        for n in missing:
            files.append({"name": n, "source": prev_files[n].get("source", ""), "size": prev_files[n].get("size", 0), "modified": "", "state": "removed"})

        issues: List[str] = []
        recorded = len((manifest or {}).get("chunks", {}))
        if manifest is None:
            state = "never_synced" if stored == 0 else "untracked"
            issues.append("The knowledge base is empty. Run a sync to build it." if stored == 0 else
                          "The knowledge base was built before synchronisation was set up. Run a sync once to start tracking changes (existing passages are kept, nothing is re-embedded).")
        else:
            changed = [f for f in files if f["state"] in ("new", "changed", "removed")]
            if changed:
                issues.append(f"{len(changed)} source file(s) changed since the last sync: " + ", ".join(f['name'] for f in changed[:4]) + (" …" if len(changed) > 4 else "") + ".")
            if stored != recorded:
                issues.append(f"The database holds {stored:,} passages but the last sync recorded {recorded:,}. Run a sync to repair this.")
            if manifest.get("embedding_model") and manifest["embedding_model"] != getattr(self.embedder, "model_name", ""):
                issues.append("The embedding model changed since the last sync. A sync will re-embed every passage.")
            if manifest.get("scope") != self.scope or bool(manifest.get("include_rev2")) != self.include_rev2:
                issues.append(f"The configured scope is '{self.scope}' but the last sync used '{manifest.get('scope')}'. Run a sync to apply the new scope.")
            state = "changes_pending" if issues else "up_to_date"
        return {"state": state, "issues": issues, "stored": stored, "recorded": recorded,
                "last_sync": (manifest or {}).get("synced_at"), "scope": self.scope, "include_rev2": self.include_rev2,
                "embedding_model": getattr(self.embedder, "model_name", ""), "counts": (manifest or {}).get("counts", {}),
                "files": files, "last_result": (manifest or {}).get("last_result"), "job": self.job_status()}

    # ------------------------------------------------------------------ plan (parses the sources)
    def plan(self) -> Dict[str, Any]:
        manifest = self.load_manifest()
        known: Dict[str, str] = (manifest or {}).get("chunks", {})
        model_changed = bool(manifest and manifest.get("embedding_model") and manifest["embedding_model"] != getattr(self.embedder, "model_name", ""))

        sources = self.loader(self.data_dir, quick=(self.scope == "quick"), include_rev2=self.include_rev2)
        parsed: Dict[str, Dict] = {}
        for name in ks.ALL_SOURCES:
            for rec in sources.get(name, []):
                parsed[rec["chunk_id"]] = rec
        with self.lock:
            stored = self.store.list_stored_chunks()

        add, update, adopt, unchanged = [], [], [], 0
        for cid, rec in parsed.items():
            if cid not in stored:
                add.append(rec)
            elif model_changed:
                update.append(rec)
            elif cid in known:
                if known[cid] != record_hash(rec):
                    update.append(rec)
                else:
                    unchanged += 1
            else:
                adopt.append(rec)  # stored, but never fingerprinted: keep it, record the fingerprint, no re-embedding
                unchanged += 1

        # stale = stored but not produced by the sources any more. A source that parsed to nothing is treated as
        # "file missing or unreadable", not as "delete everything", so a bad copy cannot wipe the knowledge base.
        empty_sources = [s for s in ks.ALL_SOURCES if not sources.get(s)]
        stale = [cid for cid, src in stored.items() if cid not in parsed and src not in empty_sources]
        protected = sorted({src for cid, src in stored.items() if cid not in parsed and src in empty_sources})
        notes: List[str] = []
        if empty_sources:
            notes.append("No passages were parsed for: " + ", ".join(empty_sources) + ". Their stored passages are kept. Check the files in data_sources/.")
        return {"parsed": parsed, "add": add, "update": update, "adopt": adopt, "unchanged": unchanged, "stale": stale,
                "protected_sources": protected, "notes": notes, "model_changed": model_changed, "stored": len(stored)}

    @staticmethod
    def plan_summary(plan: Dict[str, Any]) -> Dict[str, Any]:
        per_source: Dict[str, Dict[str, int]] = {}
        for key in ("add", "update"):
            for rec in plan[key]:
                s = per_source.setdefault(rec["knowledge_source"], {"add": 0, "update": 0})
                s[key] += 1
        return {"to_add": len(plan["add"]), "to_update": len(plan["update"]), "unchanged": plan["unchanged"], "stale": len(plan["stale"]),
                "adopted": len(plan["adopt"]), "model_changed": plan["model_changed"], "per_source": per_source, "notes": plan["notes"],
                "parsed_total": len(plan["parsed"])}

    # ------------------------------------------------------------------ sync
    def sync(self, prune: bool = False, dry_run: bool = False, progress: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, Any]:
        t0 = time.time()
        progress = progress or (lambda phase, done, total: None)
        progress("Reading the source files", 0, 0)
        plan = self.plan()
        summary = self.plan_summary(plan)
        if dry_run:
            return {"dry_run": True, **summary, "seconds": round(time.time() - t0, 1)}

        manifest = self.load_manifest() or {}
        chunks: Dict[str, str] = dict(manifest.get("chunks", {}))
        todo = plan["add"] + plan["update"]
        failed = 0
        if todo:
            with self.lock:
                self.store.ensure_collection(recreate=False)
        done = 0
        for i in range(0, len(todo), self.batch_size):
            batch = todo[i:i + self.batch_size]
            try:
                with self.lock:  # searches by analysts can run between batches
                    vectors = self.embedder.embed_texts([r["search_text"] for r in batch], batch_size=self.batch_size)
                    self.store.upsert_batch(batch, vectors)
                for r in batch:
                    chunks[r["chunk_id"]] = record_hash(r)
                done += len(batch)
            except Exception as exc:  # keep going: one bad batch must not stop the rest
                failed += len(batch)
                logger.error("Sync batch failed at offset %d: %s", i, exc)
            progress("Embedding new and changed passages", i + len(batch), len(todo))
        for r in plan["adopt"]:
            chunks[r["chunk_id"]] = record_hash(r)

        removed = 0
        if prune and plan["stale"]:
            progress("Removing stale passages", 0, len(plan["stale"]))
            with self.lock:
                removed = self.store.delete_chunks(plan["stale"])
            for cid in plan["stale"]:
                chunks.pop(cid, None)
        # manifest only lists passages that are really in the database
        live = set(plan["parsed"])
        stale_kept = set() if prune else set(plan["stale"])
        chunks = {c: h for c, h in chunks.items() if c in live or c in stale_kept}

        counts: Dict[str, int] = {}
        for cid in chunks:
            rec = plan["parsed"].get(cid)
            if rec:
                counts[rec["knowledge_source"]] = counts.get(rec["knowledge_source"], 0) + 1
        result = {**summary, "added_or_updated": done, "failed": failed, "removed": removed,
                  "stale_left": 0 if prune else len(plan["stale"]), "seconds": round(time.time() - t0, 1), "finished_at": now_text()}
        if failed == 0:  # a partly failed sync must not be recorded as a clean one
            files = self._fingerprints(manifest.get("files", {}))
        else:
            files = manifest.get("files", {})
        self._write_manifest({"version": MANIFEST_VERSION, "synced_at": now_text(), "embedding_model": getattr(self.embedder, "model_name", ""),
                              "scope": self.scope, "include_rev2": self.include_rev2, "files": files, "chunks": chunks,
                              "counts": counts, "last_result": result})
        progress("Done", 1, 1)
        return result

    def record_after_ingest(self, sources: Dict[str, List[Dict]], recreate: bool) -> None:
        """Called by scripts/ingest_sources.py so a normal ingest also starts (or refreshes) the manifest."""
        manifest = {} if recreate else (self.load_manifest() or {})
        chunks = dict(manifest.get("chunks", {}))
        counts: Dict[str, int] = {}
        for name, recs in sources.items():
            for r in recs:
                chunks[r["chunk_id"]] = record_hash(r)
            counts[name] = len(recs)
        self._write_manifest({"version": MANIFEST_VERSION, "synced_at": now_text(), "embedding_model": getattr(self.embedder, "model_name", ""),
                              "scope": self.scope, "include_rev2": self.include_rev2,
                              "files": self._fingerprints(manifest.get("files", {})), "chunks": chunks, "counts": counts, "last_result": None})

    # ------------------------------------------------------------------ background job (used by the web app)
    def job_status(self) -> Dict[str, Any]:
        with self._job_lock:
            return dict(self._job)

    def start_job(self, prune: bool = False) -> Dict[str, Any]:
        with self._job_lock:
            if self._job.get("state") == "running":
                return dict(self._job, already_running=True)
            self._job = {"state": "running", "phase": "Starting", "done": 0, "total": 0, "started": now_text(), "prune": prune}

        def report(phase: str, done: int, total: int) -> None:
            with self._job_lock:
                self._job.update(phase=phase, done=done, total=total)

        def run() -> None:
            try:
                result = self.sync(prune=prune, progress=report)
                with self._job_lock:
                    self._job = {"state": "done", "finished": now_text(), "result": result}
            except Exception as exc:
                logger.exception("Dataset sync failed")
                with self._job_lock:
                    self._job = {"state": "failed", "finished": now_text(), "error": str(exc)[:300]}

        threading.Thread(target=run, name="serc-dataset-sync", daemon=True).start()
        return self.job_status()
