"""Admin maintenance — refresh structured DB and embeddings."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class RefreshEmbeddingsRequest(BaseModel):
    pipeline: str = Field(default="both", pattern="^(both|docling|original)$")


@router.post("/admin/refresh-structured")
def refresh_structured():
    """Re-init Postgres schema and re-seed platform structured data."""
    try:
        from app.database.postgres import init_schema

        init_schema()
        subprocess.run(
            [sys.executable, "scripts/seed_platform_data.py"],
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            check=True,
            capture_output=True,
            text=True,
        )
        from app.database import postgres

        return {
            "ok": True,
            "postgres": postgres.backend_name(),
            "message": "Structured database refreshed (schema + seed data)",
        }
    except subprocess.CalledProcessError as exc:
        raise HTTPException(500, exc.stderr or str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@router.post("/admin/refresh-embeddings")
def refresh_embeddings(req: RefreshEmbeddingsRequest = RefreshEmbeddingsRequest()):
    """Sync FAISS chunk indexes into Qdrant (both pipelines by default)."""
    pipeline = req.pipeline
    try:
        from app.ingestion.qdrant_indexer import sync_pipeline_to_qdrant
        from app.retrieval.qdrant_store import get_qdrant_store

        store = get_qdrant_store()
        if not store.is_available():
            raise HTTPException(
                503,
                "Qdrant unavailable — start with: docker compose up -d qdrant",
            )
        pipelines = ["docling", "original"] if pipeline == "both" else [pipeline]
        counts = {}
        for p in pipelines:
            counts[p] = sync_pipeline_to_qdrant(p)
        return {
            "ok": True,
            "pipelines": counts,
            "total": sum(counts.values()),
            "message": f"Synced {sum(counts.values())} embedding chunks to Qdrant",
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@router.post("/admin/clear-enrollment")
def clear_enrollment():
    """Remove all enrolled documents (vectors + structured). Keeps platform seed data."""
    try:
        from app.ingestion.clear_enrollment import clear_all_enrollment

        return clear_all_enrollment()
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@router.post("/admin/refresh-all")
def refresh_all():
    """Refresh structured Postgres data and Qdrant embeddings."""
    structured = refresh_structured()
    try:
        embeddings = refresh_embeddings(RefreshEmbeddingsRequest(pipeline="both"))
    except HTTPException as exc:
        embeddings = {"ok": False, "error": exc.detail}
    return {"ok": True, "structured": structured, "embeddings": embeddings}
