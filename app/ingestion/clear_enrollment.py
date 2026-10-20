"""Clear all enrolled documents (vectors + structured) for fresh upload."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import config


def clear_all_enrollment() -> dict[str, Any]:
    """Remove indexed documents from FAISS, Qdrant, Mongo, Neo4j, Postgres docs, uploads."""
    report: dict[str, Any] = {}

    # FAISS + BM25 per pipeline
    for pipeline in ("docling", "original"):
        path = config.VECTOR_DB_PATH / pipeline
        if path.exists():
            shutil.rmtree(path)
            report[f"faiss_{pipeline}"] = "cleared"
        else:
            report[f"faiss_{pipeline}"] = "empty"

    # Qdrant — recreate collection
    try:
        from app.retrieval.qdrant_store import get_qdrant_store

        store = get_qdrant_store()
        if store.is_available():
            store.create_collection(recreate=True)
            report["qdrant"] = "recreated"
        else:
            report["qdrant"] = "unavailable"
    except Exception as exc:
        report["qdrant"] = f"error: {exc}"

    # Mongo structured IR.21 facts
    try:
        from shared.mongo_store import get_structured_store

        mongo = get_structured_store()
        names = mongo.list_documents()
        for fn in names:
            mongo.delete_by_file_name(fn)
        report["mongo"] = {"cleared": len(names), "backend": mongo.backend}
    except Exception as exc:
        report["mongo"] = f"error: {exc}"

    # Entity graph
    try:
        from shared.neo4j_store import get_graph_store

        graph = get_graph_store()
        graph.clear_all()
        report["graph"] = f"{graph.backend} cleared"
    except Exception as exc:
        report["graph"] = f"error: {exc}"

    # Postgres indexed documents (keep platform seed: dictionary, attacks, subscribers)
    try:
        from app.database import postgres

        if postgres.is_available():
            n_tables = postgres.execute("DELETE FROM document_tables")
            n_docs = postgres.execute("DELETE FROM documents")
            report["postgres"] = {"documents_deleted": n_docs, "tables_deleted": n_tables}
        else:
            report["postgres"] = "unavailable"
    except Exception as exc:
        report["postgres"] = f"error: {exc}"

    try:
        from ir21 import postgres as ir21_pg

        if ir21_pg.is_available():
            conn = ir21_pg.connect()
            with conn.cursor() as cur:
                cur.execute("DELETE FROM ir21_document")
            conn.close()
            report["ir21_postgres"] = "cleared"
        else:
            report["ir21_postgres"] = "unavailable"
    except Exception as exc:
        report["ir21_postgres"] = f"error: {exc}"

    # Uploaded files
    uploads = config.PROJECT_ROOT / "data" / "uploads"
    removed = 0
    if uploads.exists():
        for f in uploads.iterdir():
            if f.is_file():
                f.unlink()
                removed += 1
    report["uploads_removed"] = removed

    # Canonical exports (docling re-extracts on next index)
    canonical = config.PROJECT_ROOT / "data" / "canonical"
    if canonical.exists():
        shutil.rmtree(canonical)
        canonical.mkdir(parents=True, exist_ok=True)
        report["canonical"] = "cleared"

    report["ok"] = True
    report["message"] = "All enrolled documents cleared. Platform seed (dictionary, alerts) kept."
    return report
