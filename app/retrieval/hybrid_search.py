"""Unified hybrid retrieval — BM25 + dense vector + structured facts via RRF."""

from __future__ import annotations

import re
from typing import Any, Optional

import config
from app.config.settings import settings
from app.ingestion.knowledge_kind import infer_knowledge_kind, kind_of_evidence
from app.retrieval.fusion import RankedItem, enforce_min_per_source, reciprocal_rank_fusion
from app.retrieval.post_fusion import refine_evidence, sparse_rrf_weight
from app.retrieval.query_terms import hard_terms, intent_alignment_score, key_identifiers, query_tokens
from shared.schema import ContentType, RetrievalResult


def hybrid_search(
    query: str,
    *,
    filters: Optional[dict[str, Any]] = None,
    top_k: int = 20,
) -> dict[str, Any]:
    """
    Retrieve and fuse evidence from document backends:
      - Qdrant dense vectors (primary)
      - BM25 + TF-IDF sparse (lexical, from chunk corpus)
    IR.21 operator records are not fused here; they are queried via SQL.
    """
    filters = dict(filters or {})
    if not filters.get("_taxonomy_hints"):
        from app.ontology.taxonomy import metadata_filters_for_query

        hints = metadata_filters_for_query(query)
        if hints:
            filters["_taxonomy_hints"] = hints
    default_pipelines = [config.DOCUMENT_PIPELINE]
    # Case 2/3 (and general Qdrant coverage): search docling standards + original tool corpus.
    requested = list(filters.get("pipelines") or [])
    if requested:
        pipelines = requested
    else:
        pipelines = list(default_pipelines)
        if "original" not in pipelines:
            pipelines.append("original")
    # Deduplicate while preserving order.
    seen_p: set[str] = set()
    uniq: list[str] = []
    for p in pipelines:
        if p and p not in seen_p:
            seen_p.add(p)
            uniq.append(p)
    pipelines = uniq or [config.DOCUMENT_PIPELINE]
    pool = max(top_k * 3, 18)
    doc = filters.get("file_name")
    file_names = filters.get("file_names")
    targets: list[str | None] = [doc] if doc else (list(file_names) if file_names else [None])

    ranked_lists: list[list[RankedItem]] = []
    backends: list[str] = []

    for pipe in pipelines:
        pipe_lists = _vector_legs(query, pipe, pool, targets, filters)
        ranked_lists.extend(pipe_lists)
        for lst in pipe_lists:
            if lst:
                backends.append(lst[0].source)

    fused = reciprocal_rank_fusion(
        ranked_lists,
        k=settings.rrf_k,
        top_k=pool,
        list_weights=_rrf_list_weights(ranked_lists, query),
    )
    fused = enforce_min_per_source(
        fused,
        min_k=int(getattr(config, "MIN_PER_SOURCE", 2) or 2),
        top_k=pool,
    )
    evidence = [item.to_evidence() for item in fused]
    evidence = _apply_scope(evidence, filters)  # soft boost only
    evidence = _apply_taxonomy_boost(evidence, filters)
    # Soft demote IR.21 filenames if they appear — never hard-drop corpus hits.
    for e in evidence:
        src = str(e.get("source") or "").lower()
        if "ir21" in src or "ir.21" in src or "raex" in src:
            e["score"] = float(e.get("score") or 0) - 4.0
    evidence = _rank_evidence_for_query(evidence, query, filters=filters)
    # Soft relevance floor: re-order / trim weakly, never exclusive keep-out.
    min_rel = float(settings.retrieval_min_relevance or 0.0)
    if min_rel > 0 and evidence:
        scored = [(ev, _evidence_relevance(ev, query)) for ev in evidence]
        scored.sort(key=lambda x: x[1], reverse=True)
        evidence = [ev for ev, _ in scored]
    evidence = _prefer_knowledge_kinds(evidence, filters)
    evidence = refine_evidence(query, evidence, top_k=top_k)

    return {
        "results": evidence,
        "evidence": evidence,
        "backend": "+".join(sorted(set(backends))) if backends else "none",
        "fusion": "rrf",
    }


def _rrf_list_weights(ranked_lists: list[list[RankedItem]], query: str) -> list[float]:
    """Boost sparse (BM25/TF-IDF) legs when the query has exact identifiers."""
    sparse_w = sparse_rrf_weight(query)
    weights: list[float] = []
    for lst in ranked_lists:
        if lst and str(lst[0].source).startswith("qdrant"):
            weights.append(1.0)
        else:
            weights.append(sparse_w)
    return weights or [1.0] * len(ranked_lists)


def _vector_legs(
    query: str,
    pipeline: str,
    pool: int,
    targets: list[str | None],
    filters: dict[str, Any],
) -> list[list[RankedItem]]:
    """Qdrant dense vectors + BM25/TF-IDF sparse legs (no FAISS)."""
    from shared.retrieval import retrieve

    lists: list[list[RankedItem]] = []

    from app.retrieval.qdrant_store import get_qdrant_store

    qdrant = get_qdrant_store()
    if qdrant.is_available():
        # Soft preferences only — never Qdrant must-filters for kind/file/pipeline.
        soft = {**filters, "pipeline": pipeline}
        soft.pop("_hard_scope", None)
        hits = qdrant.search(query, top_k=pool, filters=soft)
        if hits:
            lists.append(_qdrant_to_ranked(hits, pipeline))
    else:
        print("[hybrid_search] Qdrant unavailable — start docker compose qdrant service")

    sparse: list[RankedItem] = []
    seen: set[str] = set()
    for target in targets:
        try:
            hits = retrieve(query, pipeline, top_k=pool, document=target, sparse_only=True)
        except (AssertionError, ValueError, FileNotFoundError) as exc:
            print(f"[hybrid_search] skip sparse {pipeline}/{target}: {exc}")
            continue
        for hit in hits:
            cid = hit.chunk.chunk_id
            if cid in seen:
                continue
            seen.add(cid)
            sparse.append(_retrieval_hit_to_ranked(hit, pipeline, query))
    if sparse:
        lists.append(sparse)

    return lists


def _qdrant_to_ranked(hits: list[dict[str, Any]], pipeline: str) -> list[RankedItem]:
    out: list[RankedItem] = []
    for rank, h in enumerate(hits, start=1):
        meta = h.get("metadata") or {}
        cid = str(h.get("chunk_id") or meta.get("chunk_id") or f"qdrant-{rank}")
        fn = meta.get("file_name") or ""
        page = meta.get("page")
        source = f"{fn} p.{page}" if page else fn
        text = h.get("text") or meta.get("text") or ""
        etype = _evidence_type(meta.get("content_type", ""), text)
        out.append(
            RankedItem(
                item_id=cid,
                rank=rank,
                source=f"qdrant:{pipeline}",
                score=float(h.get("score", 0)),
                payload={
                    "type": etype,
                    "source": source,
                    "body": text,
                    "chunk_id": cid,
                    "section": meta.get("section", ""),
                    "knowledge_kind": meta.get("knowledge_kind")
                    or infer_knowledge_kind(fn, source=str(meta.get("source") or "")),
                },
            )
        )
    return out


def _retrieval_hit_to_ranked(hit: RetrievalResult, pipeline: str, query: str) -> RankedItem:
    c = hit.chunk
    body = _format_chunk_body(c, query)
    etype = _chunk_evidence_type(c)
    source = c.file_name or ""
    if c.page:
        source = f"{source} p.{c.page}"
    return RankedItem(
        item_id=c.chunk_id,
        rank=hit.rank,
        source=f"bm25+tfidf:{pipeline}",
        score=float(hit.score),
        payload={
            "type": etype,
            "source": source,
            "body": body,
            "chunk_id": c.chunk_id,
            "section": c.section or "",
            "toc_path": c.toc_path or "",
            "knowledge_kind": infer_knowledge_kind(c.file_name or ""),
        },
    )


def _structured_ranked(
    query: str,
    *,
    file_name: str | None,
    file_names: list[str] | None,
    tadig: str | None,
    document_id: str | None,
    limit: int,
) -> list[RankedItem]:
    try:
        from shared.mongo_store import get_structured_store

        store = get_structured_store()
        data = store.search_facts(
            query,
            file_name=file_name,
            file_names=file_names,
            tadig=tadig,
            document_id=document_id,
            limit=limit,
        )
    except Exception:
        return []

    items: list[tuple[float, RankedItem]] = []

    for ep in data.get("endpoints") or []:
        score = float(ep.get("_score") or 0)
        role = ep.get("role") or ep.get("node_type") or "Endpoint"
        value = ep.get("gt_address") or ep.get("fqdn") or ep.get("ip") or ""
        if not value:
            value = ", ".join(p for p in (ep.get("protocol"), ep.get("node_type")) if p)
        fn = ep.get("file_name") or ""
        page = ep.get("page")
        src = f"{fn} p.{page}" if page else fn
        eid = f"ep:{fn}:{role}:{value}"
        items.append((
            score,
            RankedItem(
                item_id=eid,
                rank=0,
                source="structured",
                score=score,
                payload={
                    "type": "Structured Facts",
                    "source": src,
                    "body": f"{role}: {value}",
                    "section": ep.get("section_id") or "",
                },
            ),
        ))

    for field in data.get("fields") or []:
        score = float(field.get("_score") or 0)
        key = field.get("field_key") or "Field"
        value = field.get("field_value") or ""
        if not value:
            continue
        fn = field.get("file_name") or ""
        page = field.get("page")
        src = f"{fn} p.{page}" if page else fn
        eid = f"field:{fn}:{key}:{value}"
        items.append((
            score,
            RankedItem(
                item_id=eid,
                rank=0,
                source="structured",
                score=score,
                payload={
                    "type": "Structured Facts",
                    "source": src,
                    "body": f"{key}: {value}",
                    "section": field.get("section_id") or "",
                },
            ),
        ))

    items.sort(key=lambda x: x[0], reverse=True)
    out: list[RankedItem] = []
    for rank, (_, item) in enumerate(items[:limit], start=1):
        item.rank = rank
        out.append(item)
    return out


def _format_chunk_body(chunk, query: str = "") -> str:
    """Render chunk text — lead with extracted field/value pairs, then context."""
    header = chunk.toc_path or chunk.section or chunk.file_name or ""
    if chunk.page:
        header += f" (p.{chunk.page})"

    parts: list[str] = []
    if header:
        parts.append(header)

    # Prefer structured field/value extraction for table chunks
    pairs = _extracted_pairs(chunk, query)
    if pairs:
        lines = ["Key values:"]
        for field, value in pairs[:10]:
            lines.append(f"- {field}: {value}")
        parts.append("\n".join(lines))
    else:
        highlights = _query_relevant_lines(chunk, query)
        if highlights:
            parts.append("Relevant values:\n" + "\n".join(f"- {line}" for line in highlights[:10]))

    if chunk.structured_table and chunk.content_type in (
        ContentType.TABLE,
        ContentType.TABLE_ROW,
    ):
        from docling_pipeline.table_serializer import serialize_table_markdown

        md = serialize_table_markdown(chunk.structured_table, max_rows=8)
        if md and md not in "\n".join(parts):
            parts.append(md)

    row_text = (chunk.content or "").strip()
    if row_text and row_text not in "\n".join(parts) and not pairs:
        parts.append(row_text[:1200])

    return "\n\n".join(parts).strip()[:2400]


def _extracted_pairs(chunk, query: str) -> list[tuple[str, str]]:
    """Extract clean Field/Value pairs from a table chunk for the LLM."""
    from app.retrieval.table_chunk_search import extract_rows_from_chunk, _rank_rows, _row_answer_score

    text = chunk.content or ""
    if chunk.structured_table and chunk.structured_table.rows:
        # Prefer serialized markdown when available in content
        pass
    rows = extract_rows_from_chunk(
        text,
        section=chunk.section or "",
        page=chunk.page,
        file_name=chunk.file_name or "",
    )
    if not rows:
        return []
    ranked = _rank_rows(rows, query)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in ranked:
        if _row_answer_score(row, query) < 1.0:
            continue
        field = str(row.get("Field", "")).strip()
        value = str(row.get("Value", "")).strip()
        if not field or not value or field == value:
            continue
        if len(value) < 3:
            continue
        key = f"{field.lower()}|{value.lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append((field, value))
    return out


_DOC_ID_RE = re.compile(r"^[a-f0-9]{24,}", re.I)
_HIGHLIGHT_NOISE = (
    "table of contents",
    "dtype: str",
    "raex ir.",
)
_BOILERPLATE_MARKERS = (
    "contact information",
    "jobtitle",
    "history of changes",
    "table of contents",
    "abbreviations",
)


def _is_valueful(line: str) -> bool:
    """A line that carries a concrete value rather than only labels."""
    low = line.lower()
    return bool(re.search(r"\d", low) or re.search(r"\b(yes|no|supported|n/a)\b", low))


def _is_highlight_noise(line: str) -> bool:
    low = line.lower().strip()
    if not low:
        return True
    if any(n in low for n in _HIGHLIGHT_NOISE):
        return True
    if _DOC_ID_RE.match(low.replace("-", "").replace("_", "")):
        return True
    # Wide raw table fragments are only useful when they carry values.
    if line.count("|") >= 3 and not _is_valueful(low):
        return True
    return False


def _query_relevant_lines(chunk, query: str) -> list[str]:
    """Extract lines from chunk/table rows that match query terms (generic)."""
    from app.retrieval.table_chunk_search import _strip_column_prefix

    tokens = {t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 3}
    blocks: list[str] = [chunk.content or ""]
    tbl = chunk.structured_table
    if tbl and tbl.rows:
        for row in tbl.rows:
            if isinstance(row, dict):
                blocks.extend(str(v) for v in row.values() if v)

    scored: list[tuple[float, str]] = []
    for block in blocks:
        for raw in block.split("\n"):
            line = re.sub(r"\s+", " ", raw).strip()
            if len(line) < 8 or "dtype: str" in line.lower():
                continue
            line = _strip_column_prefix(line)
            if not line or _is_highlight_noise(line):
                continue
            low = line.lower()
            keys = key_identifiers(query)
            has_key = any(k in low for k in keys)
            if tokens and not any(t in low for t in tokens) and not has_key:
                continue
            score = sum(0.2 for t in tokens if t in low)
            if has_key:
                score += 2.0
            if _is_valueful(low):
                score += 1.0
            scored.append((score, line[:160]))

    scored.sort(key=lambda x: x[0], reverse=True)
    found: list[str] = []
    for _, line in scored:
        if line not in found:
            found.append(line)
    return found


def _evidence_relevance(ev: dict[str, Any], query: str) -> float:
    """Query-term relevance score used to drop weak vector hits."""
    tokens = query_tokens(query)
    hard = hard_terms(query) | key_identifiers(query)
    blob = f"{ev.get('body','')} {ev.get('section','')} {ev.get('source','')}".lower()
    section = (ev.get("section") or "").lower()
    score = float(ev.get("score", 0))
    score += sum(0.2 for t in tokens if t in blob)
    hard_hits = sum(1 for t in hard if t in blob)
    score += hard_hits * 1.2
    if hard and hard_hits == 0:
        score -= 2.5
    if section and any(t in section for t in hard):
        score += 2.0
    return score


def _apply_taxonomy_boost(
    evidence: list[dict[str, Any]],
    filters: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    hints = (filters or {}).get("_taxonomy_hints") or {}
    if not hints:
        return evidence
    try:
        from app.ingestion.chunk_taxonomy import taxonomy_boost_score
    except ImportError:
        return evidence
    boosted: list[dict[str, Any]] = []
    for ev in evidence:
        row = dict(ev)
        row["score"] = float(row.get("score") or 0) + taxonomy_boost_score(row, hints)
        boosted.append(row)
    return boosted


def _rank_evidence_for_query(
    evidence: list[dict[str, Any]],
    query: str,
    *,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Re-rank fused evidence by query term overlap + taxonomy FS primary."""
    tokens = query_tokens(query)
    hard = hard_terms(query) | key_identifiers(query)
    keys = key_identifiers(query)
    hints = (filters or {}).get("_taxonomy_hints") or {}
    primary = str(hints.get("primary_fs_doc") or "").lower()
    demoted = {str(d).lower() for d in (hints.get("demoted_fs_docs") or [])}

    def relevance(ev: dict[str, Any]) -> float:
        blob = f"{ev.get('body','')} {ev.get('section','')} {ev.get('source','')}".lower()
        section = (ev.get("section") or "").lower()
        score = float(ev.get("score", 0))
        score += sum(0.2 for t in tokens if t in blob)
        hard_hits = sum(1 for t in hard if t in blob)
        score += hard_hits * 1.2
        # Soft preference only — missing hard terms never exclude a hit.
        if hard and hard_hits == 0:
            score -= 0.8
        if ev.get("type") == "Table":
            score += 0.8
        if section and any(t in section for t in hard):
            score += 2.0
        if keys and any(k in blob for k in keys) and _is_valueful(blob):
            score += 1.5
        if hard and hard_hits == 0 and any(n in blob for n in _BOILERPLATE_MARKERS):
            score -= 1.5
        # Soft intent alignment (e.g. session establishment → Create Session).
        score += intent_alignment_score(blob, query)
        # Soft FS preference — never exclusive keep-out.
        if primary and primary in blob:
            score += 6.0
        elif "fs.21" in blob and primary:
            score -= 2.0
        for tag in demoted:
            if tag in blob:
                score -= 3.0
        return score

    ranked = sorted(evidence, key=relevance, reverse=True)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for ev in ranked:
        key = f"{ev.get('source')}|{ev.get('section')}|{str(ev.get('body',''))[:60]}"
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)
    return out


def _chunk_evidence_type(chunk) -> str:
    if chunk.content_type in (ContentType.TABLE, ContentType.TABLE_ROW):
        return "Table"
    return "Document"


def _evidence_type(content_type: str, text: str) -> str:
    ct = (content_type or "").lower()
    if "table" in ct:
        return "Table"
    if "table" in (text or "").lower()[:200]:
        return "Table"
    return "Document"


def _prefer_knowledge_kinds(
    evidence: list[dict[str, Any]],
    filters: dict[str, Any],
) -> list[dict[str, Any]]:
    """Soft-boost matching vector namespaces — never drop other kinds."""
    wanted = filters.get("knowledge_kinds") or filters.get("knowledge_kind")
    if not wanted:
        return evidence
    if isinstance(wanted, str):
        wanted = [wanted]
    wanted_set = {str(k) for k in wanted}
    for item in evidence:
        kind = str(item.get("knowledge_kind") or kind_of_evidence(item) or "")
        item["knowledge_kind"] = kind
        if kind in wanted_set:
            item["score"] = float(item.get("score") or 0) + 2.5
    return sorted(evidence, key=lambda e: float(e.get("score") or 0), reverse=True)


def _apply_scope(evidence: list[dict[str, Any]], filters: dict[str, Any]) -> list[dict[str, Any]]:
    """Soft document preference — never hard-drop out-of-scope chunks."""
    if not filters:
        return evidence
    fn = filters.get("file_name")
    names = set(filters.get("file_names") or [])
    if fn:
        names.add(fn)
    if not names:
        return evidence
    for ev in evidence:
        src = str(ev.get("source") or "")
        if any(n in src for n in names):
            ev["score"] = float(ev.get("score") or 0) + 3.0
        else:
            ev["score"] = float(ev.get("score") or 0) - 0.5
    return evidence
