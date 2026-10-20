"""Infer document / pipeline scope from query text (delegates to document registry)."""

from __future__ import annotations

from typing import Any

from app.retrieval.document_registry import infer_retrieval_scope


def infer_scope(
    query: str,
    *,
    document: str | None = None,
    entities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return optional file_name(s), tadig, document_id, and pipelines for retrieval."""
    return infer_retrieval_scope(query, document=document, entities=entities)
