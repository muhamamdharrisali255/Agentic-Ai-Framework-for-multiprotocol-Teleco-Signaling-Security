"""Hierarchical context expansion after vector retrieval.

Uses parent / prev / next / table relationships stored in Qdrant payloads
(or an optional in-memory chunk map) to reconstruct surrounding context.

Lookups are scoped by document_id/file_name because bare chunk_ids collide
across FS.11 / FS.19 / FS.20 / FS.21 in the shared corpus.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

import config
from app.retrieval.lexical_query import evidence_key, is_front_matter_evidence

logger = logging.getLogger(__name__)

LookupFn = Callable[..., Optional[dict[str, Any]]]


def _payload_as_evidence(payload: dict[str, Any], *, score: float, role: str) -> dict[str, Any]:
    meta = dict(payload)
    text = str(payload.get("text") or payload.get("content") or "")
    return {
        "type": "Document",
        "source": payload.get("file_name") or payload.get("document_id") or "qdrant",
        "body": text,
        "score": float(score),
        "structured": False,
        "section": payload.get("section") or "",
        "page": payload.get("page"),
        "chunk_id": payload.get("chunk_id"),
        "metadata": meta,
        "pipeline": payload.get("pipeline"),
        "knowledge_kind": payload.get("knowledge_kind"),
        "expansion_role": role,
        "content_type": payload.get("content_type") or "",
        "toc_path": payload.get("toc_path") or "",
        "parent_id": payload.get("parent_id"),
        "prev_chunk_id": payload.get("prev_chunk_id"),
        "next_chunk_id": payload.get("next_chunk_id"),
        "table_id": payload.get("table_id"),
        "row_id": payload.get("row_id"),
        "entities": payload.get("entities") or payload.get("entity_types") or [],
        "document_id": payload.get("document_id"),
    }


def _lookup_from_qdrant(
    chunk_id: str,
    *,
    document_id: str | None = None,
    file_name: str | None = None,
) -> Optional[dict[str, Any]]:
    if not chunk_id:
        return None
    try:
        from app.retrieval.qdrant_store import get_qdrant_store

        rows = get_qdrant_store().get_chunks_by_ids(
            [chunk_id],
            limit=4,
            document_id=document_id,
            file_name=file_name,
        )
        return rows[0] if rows else None
    except Exception as exc:
        logger.debug("context_expand qdrant lookup failed chunk_id=%s: %s", chunk_id, exc)
        return None


def expand_retrieval_hits(
    hits: list[dict[str, Any]],
    *,
    lookup: Optional[LookupFn] = None,
    prev_n: int | None = None,
    next_n: int | None = None,
    parent_depth: int | None = None,
    max_chars: int | None = None,
) -> list[dict[str, Any]]:
    """Expand top hits with parent / neighbors / parent TABLE; dedupe; cap chars."""
    if not hits:
        return []

    prev_n = config.CONTEXT_PREV_CHUNKS if prev_n is None else prev_n
    next_n = config.CONTEXT_NEXT_CHUNKS if next_n is None else next_n
    parent_depth = config.CONTEXT_PARENT_DEPTH if parent_depth is None else parent_depth
    max_chars = config.MAX_RETRIEVAL_CONTEXT_CHARS if max_chars is None else max_chars

    cache: dict[str, dict[str, Any]] = {}
    for h in hits:
        meta = dict(h.get("metadata") or {})
        if h.get("text") and not meta.get("text"):
            meta["text"] = h.get("text")
        if h.get("body") and not meta.get("text"):
            meta["text"] = h.get("body")
        if h.get("chunk_id") and not meta.get("chunk_id"):
            meta["chunk_id"] = h["chunk_id"]
        if h.get("document_id") and not meta.get("document_id"):
            meta["document_id"] = h["document_id"]
        if h.get("source") and not meta.get("file_name"):
            meta.setdefault("file_name", h.get("source"))
        key = evidence_key({**meta, **{k: h.get(k) for k in ("chunk_id", "document_id", "source")}})
        if key and "||" in key:
            cache[key] = meta

    def resolve(cid: str, *, document_id: str | None = None, file_name: str | None = None):
        if lookup is not None:
            try:
                return lookup(cid, document_id=document_id, file_name=file_name)
            except TypeError:
                return lookup(cid)
        return _lookup_from_qdrant(cid, document_id=document_id, file_name=file_name)

    def get_payload(
        cid: str | None,
        *,
        document_id: str | None = None,
        file_name: str | None = None,
    ) -> Optional[dict[str, Any]]:
        if not cid:
            return None
        if document_id or file_name:
            scoped = evidence_key(
                {"chunk_id": cid, "document_id": document_id, "source": file_name}
            )
            if scoped in cache:
                return cache[scoped]
        for _k, v in cache.items():
            if str(v.get("chunk_id") or "") != cid:
                continue
            if document_id and str(v.get("document_id") or "") not in ("", str(document_id)):
                continue
            if file_name and str(v.get("file_name") or "") not in ("", str(file_name)):
                continue
            return v
        row = resolve(cid, document_id=document_id, file_name=file_name)
        if row:
            cache[evidence_key(row)] = row
        return row

    ordered: list[tuple[int, float, dict[str, Any]]] = []
    seen: set[str] = set()

    def add(payload: Optional[dict[str, Any]], *, score: float, role: str, tier: int) -> None:
        if not payload:
            return
        # Never expand into copyright/TOC/disclaimer neighbors.
        if role != "match" and is_front_matter_evidence(payload):
            return
        key = evidence_key(payload)
        if not key or key in seen:
            return
        text = str(payload.get("text") or payload.get("content") or payload.get("body") or "").strip()
        if not text:
            return
        seen.add(key)
        ordered.append((tier, -float(score), _payload_as_evidence(payload, score=score, role=role)))

    for h in hits:
        meta = dict(h.get("metadata") or {})
        score = float(h.get("score") or 0.0)
        cid = str(h.get("chunk_id") or meta.get("chunk_id") or "")
        doc_id = str(h.get("document_id") or meta.get("document_id") or "")
        file_name = str(meta.get("file_name") or h.get("source") or "")
        seed = {
            **meta,
            "chunk_id": cid,
            "document_id": doc_id or meta.get("document_id"),
            "file_name": file_name or meta.get("file_name"),
            "text": h.get("body") or h.get("text") or meta.get("text"),
            "section": h.get("section") or meta.get("section"),
            "content_type": h.get("content_type") or meta.get("content_type"),
            "parent_id": h.get("parent_id") or meta.get("parent_id"),
            "prev_chunk_id": h.get("prev_chunk_id") or meta.get("prev_chunk_id"),
            "next_chunk_id": h.get("next_chunk_id") or meta.get("next_chunk_id"),
        }
        if cid:
            cache[evidence_key(seed)] = seed
        add(seed, score=score, role="match", tier=0)

        ct = str(seed.get("content_type") or "").lower()
        if ct in {"table_row", "table-row"} and seed.get("parent_id"):
            add(
                get_payload(
                    str(seed["parent_id"]),
                    document_id=doc_id or None,
                    file_name=file_name or None,
                ),
                score=score * 0.95,
                role="table_parent",
                tier=1,
            )

        pid = seed.get("parent_id")
        depth = 0
        while pid and depth < parent_depth:
            parent = get_payload(str(pid), document_id=doc_id or None, file_name=file_name or None)
            if not parent:
                break
            add(parent, score=score * (0.9 - 0.05 * depth), role="parent", tier=1)
            pid = parent.get("parent_id")
            depth += 1

        cur_prev = seed.get("prev_chunk_id")
        for i in range(max(0, prev_n)):
            if not cur_prev:
                break
            prev = get_payload(str(cur_prev), document_id=doc_id or None, file_name=file_name or None)
            if not prev:
                break
            add(prev, score=score * (0.85 - 0.05 * i), role="prev", tier=2)
            cur_prev = prev.get("prev_chunk_id")

        cur_next = seed.get("next_chunk_id")
        for i in range(max(0, next_n)):
            if not cur_next:
                break
            nxt = get_payload(str(cur_next), document_id=doc_id or None, file_name=file_name or None)
            if not nxt:
                break
            add(nxt, score=score * (0.85 - 0.05 * i), role="next", tier=2)
            cur_next = nxt.get("next_chunk_id")

    ordered.sort(key=lambda t: (t[0], t[1]))
    # Preserve original hit order for tier-0 matches when scores are CE vs BM25 mixed:
    # re-sort only within the same tier+score band is already done; but if callers
    # promoted inventories, keep match order by walking hits first.
    match_order = {
        evidence_key(
            {
                "chunk_id": h.get("chunk_id") or (h.get("metadata") or {}).get("chunk_id"),
                "document_id": h.get("document_id") or (h.get("metadata") or {}).get("document_id"),
                "source": h.get("source") or (h.get("metadata") or {}).get("file_name"),
            }
        ): i
        for i, h in enumerate(hits)
    }

    def _stable_key(item: tuple[int, float, dict[str, Any]]) -> tuple:
        tier, neg_score, ev = item
        if tier == 0:
            return (0, match_order.get(evidence_key(ev), 10_000), neg_score)
        return (tier, 0, neg_score)

    ordered.sort(key=_stable_key)
    out: list[dict[str, Any]] = []
    used = 0
    for _, __, ev in ordered:
        body = str(ev.get("body") or "")
        if used and max_chars and used + len(body) > max_chars:
            continue
        out.append(ev)
        used += len(body)
        if max_chars and used >= max_chars:
            break

    logger.info(
        "context_expanded hits=%s expanded=%s chars=%s",
        len(hits),
        len(out),
        used,
    )
    return out or [ordered[0][2]] if ordered else []


def expand_evidence_list(
    evidence: list[dict[str, Any]],
    *,
    lookup: Optional[LookupFn] = None,
) -> list[dict[str, Any]]:
    """Adapter: evidence dicts → expand_retrieval_hits → evidence dicts."""
    hits = []
    for ev in evidence:
        meta = dict(ev.get("metadata") or {})
        for key in (
            "chunk_id",
            "document_id",
            "content_type",
            "parent_id",
            "prev_chunk_id",
            "next_chunk_id",
            "table_id",
            "section",
            "toc_path",
            "file_name",
            "text",
        ):
            if ev.get(key) is not None and key not in meta:
                meta[key] = ev[key]
        if ev.get("body") and not meta.get("text"):
            meta["text"] = ev["body"]
        if ev.get("source") and not meta.get("file_name"):
            meta["file_name"] = ev["source"]
        hits.append(
            {
                "chunk_id": ev.get("chunk_id") or meta.get("chunk_id"),
                "document_id": ev.get("document_id") or meta.get("document_id"),
                "source": ev.get("source") or meta.get("file_name"),
                "section": ev.get("section"),
                "content_type": ev.get("content_type"),
                "body": ev.get("body"),
                "text": ev.get("body") or meta.get("text") or "",
                "score": float(ev.get("score") or 0.0),
                "metadata": meta,
            }
        )
    return expand_retrieval_hits(hits, lookup=lookup)
