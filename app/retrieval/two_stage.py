"""Two-stage document retrieval: metadata first, then chunks.

Round 1 ranks enrolled documents (source, protocol, filename, section hints).
Round 2 searches chunks only inside that set when the metadata match is strong
enough; otherwise it searches the full prose corpus.
"""

from __future__ import annotations

from typing import Any

from app.ingestion.knowledge_kind import infer_knowledge_kind
from app.retrieval.document_registry import resolve_documents
from app.retrieval.hybrid_search import hybrid_search


def round1_documents(
    query: str,
    *,
    document: str | None = None,
    entities: dict[str, Any] | None = None,
    knowledge_kinds: list[str] | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    from app.ontology.taxonomy import demoted_fs_documents_for_query, primary_fs_document

    candidates = resolve_documents(query, document=document, entities=entities)
    wanted = set(knowledge_kinds or [])
    primary = primary_fs_document(query)
    demoted = {d.lower() for d in demoted_fs_documents_for_query(query)}
    out: list[dict[str, Any]] = []
    for c in candidates:
        kind = infer_knowledge_kind(c.file_name, source=c.source or "")
        score = float(c.score)
        if _looks_like_ir21(c.file_name):
            score -= 8.0  # soft demote — never hard-skip
        if wanted and kind in wanted:
            score += 6.0
        fn_low = (c.file_name or "").lower()
        if primary and primary.lower() in fn_low:
            score += 20.0
        # Soft demote wrong-protocol docs; keep FS.21 when primary is missing from catalog.
        primary_present = bool(primary) and any(
            primary.lower() in (x.file_name or "").lower() for x in candidates
        )
        if primary_present and any(tag in fn_low for tag in demoted):
            score -= 12.0
        elif (not primary_present) and any(
            tag in fn_low for tag in demoted if tag != "fs.21"
        ):
            score -= 12.0
        out.append(
            {
                "file_name": c.file_name,
                "pipeline": c.pipeline,
                "score": round(score, 2),
                "source": c.source,
                "tadig": c.tadig,
                "knowledge_kind": kind,
                "match_reasons": c.match_reasons,
            }
        )
    out.sort(key=lambda r: r["score"], reverse=True)
    return out[:limit]


def round1_to_filters(
    round1: list[dict[str, Any]],
    base: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Soft Round-1 document preferences for Round-2 — never hard-pin file_name.

    Preferred docs go into candidate_scores for boost-only ranking.
    """
    import config

    filters = dict(base or {})
    filters.pop("_query", None)

    if not round1:
        return filters

    # Soft preference scores only — Qdrant search stays unfiltered.
    scores = {
        str(r["file_name"]): float(r.get("score") or 0)
        for r in round1[:8]
        if r.get("file_name")
    }
    if scores:
        filters["candidate_scores"] = scores
        # Keep names as soft hints (boosted in search/rerank), not must-filters.
        filters["file_names"] = list(scores.keys())[:5]
        filters.pop("file_name", None)

    pipelines = sorted({str(r.get("pipeline")) for r in round1 if r.get("pipeline")})
    preferred = config.DOCUMENT_PIPELINE
    if preferred in pipelines:
        pipelines = [preferred, "original"] if "original" in {
            str(r.get("pipeline")) for r in round1
        } else [preferred]
    if not pipelines:
        pipelines = [preferred, "original"]
    filters["pipelines"] = list(dict.fromkeys(pipelines))
    return filters


def round2_chunks(
    query: str,
    *,
    filters: dict[str, Any],
    top_k: int,
) -> dict[str, Any]:
    filters = dict(filters or {})
    filters.setdefault("_query", query)
    if filters.get("_pure_vector"):
        from app.retrieval.pure_vector import pure_qdrant_search

        return pure_qdrant_search(query, top_k=top_k, filters=filters)
    return hybrid_search(query, filters=filters, top_k=top_k)


def _looks_like_ir21(file_name: str) -> bool:
    fn = (file_name or "").lower()
    return "ir21" in fn or "ir.21" in fn or "raex" in fn
