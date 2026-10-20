"""Case 2/3 retrieval — dense cosine + BM25 lexical → cross-encoder.

Keeps the current telecom Qwen-1.5B embedder vectors. No taxonomy/CAT hardfixes.

Instruct-embed cosine ranks are tightly clustered, so the dense over-fetch stays
wide for the reranker. BM25 adds opcode/hex/cause-code hits the embedder misses.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import config
from app.retrieval.fusion import RankedItem, reciprocal_rank_fusion
from app.retrieval.lexical_query import (
    bm25_query_variants,
    chunk_record_key,
    evidence_key,
    is_front_matter_evidence,
    is_message_inventory,
    is_message_list_intent,
    is_table_like,
    is_weak_message_list_context,
)
from app.retrieval.qdrant_store import get_qdrant_store
from app.retrieval.post_fusion import sparse_rrf_weight

_TOC_STUB_RE = re.compile(
    r"(?is)^\s*Document:.*Table of Contents(?:\s+path:)?",
)
_PROSE_HINT_RE = re.compile(
    r"(?i)\b(should not|must not|refers to|this (?:refers|countermeasure)|"
    r"application packet|signalling message|points-of-interconnect|POI)\b",
)


def _merge_same_section_siblings(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join over-split paragraphs from the same file+section before CE scoring."""
    order: list[str] = []
    groups: dict[str, dict[str, Any]] = {}
    for ev in evidence:
        src = str(ev.get("source") or "")
        sec = str(ev.get("section") or "").split("|")[0].strip()
        key = f"{src}||{sec}".lower()
        body = str(ev.get("body") or "").strip()
        if key not in groups:
            order.append(key)
            groups[key] = dict(ev)
            continue
        cur = groups[key]
        cur_body = str(cur.get("body") or "")
        if body and body not in cur_body:
            cur["body"] = f"{cur_body}\n\n{body}".strip()
        if float(ev.get("score") or 0) > float(cur.get("score") or 0):
            cur["score"] = ev["score"]
    return [groups[k] for k in order]


def _hit_to_evidence(h: dict[str, Any]) -> dict[str, Any]:
    meta = dict(h.get("metadata") or {})
    text = str(h.get("text") or meta.get("text") or h.get("content") or "")
    doc_id = h.get("document_id") or meta.get("document_id") or ""
    file_name = meta.get("file_name") or h.get("file_name") or ""
    return {
        "type": "Document",
        "source": file_name or doc_id or "qdrant",
        "body": text,
        "score": float(h.get("score") or 0.0),
        "structured": False,
        "section": h.get("section") or meta.get("section") or "",
        "page": h.get("page") if h.get("page") is not None else meta.get("page"),
        "chunk_id": h.get("chunk_id") or meta.get("chunk_id"),
        "metadata": meta,
        "pipeline": h.get("pipeline") or meta.get("pipeline"),
        "knowledge_kind": meta.get("knowledge_kind"),
        "document_id": doc_id,
        "content_type": h.get("content_type") or meta.get("content_type"),
        "toc_path": h.get("toc_path") or meta.get("toc_path"),
        "parent_id": h.get("parent_id") or meta.get("parent_id"),
        "prev_chunk_id": h.get("prev_chunk_id") or meta.get("prev_chunk_id"),
        "next_chunk_id": h.get("next_chunk_id") or meta.get("next_chunk_id"),
        "table_id": h.get("table_id") or meta.get("table_id"),
        "row_id": h.get("row_id") or meta.get("row_id"),
        "entities": h.get("entities") or meta.get("entities") or [],
    }


def _bm25_body_usable(body: str) -> bool:
    """Drop pure TOC listings; keep stubs that still carry a section summary/prose."""
    text = (body or "").strip()
    if len(text) < 80:
        return False
    if _TOC_STUB_RE.match(text) and not _PROSE_HINT_RE.search(text):
        return False
    return True


def _strip_toc_prefix(body: str) -> str:
    """Prefer the prose after Docling TOC headers when present."""
    text = body or ""
    for marker in ("Section summary:", "\n\n"):
        idx = text.find(marker)
        if idx >= 0 and idx < 400:
            rest = text[idx + len(marker) :].strip()
            if len(rest) >= 60:
                return rest
    return text


def _bm25_leg(
    query: str,
    *,
    top_k: int,
    file_name: str | None = None,
) -> list[RankedItem]:
    """Lexical BM25 over local chunk corpora (opcodes, cause codes, hex, section ids).

    Runs multiple generic query variants (cleaned content + optional message-table
    anchors) and keeps the best rank per chunk — no protocol/opcode hardfixes.
    """
    from shared.bm25_store import get_bm25_store

    best: dict[str, RankedItem] = {}
    pipelines = []
    for p in ("docling", "original", getattr(config, "DOCUMENT_PIPELINE", "docling")):
        if p and p not in pipelines:
            pipelines.append(p)
    variants = bm25_query_variants(query)
    for pipeline in pipelines:
        store = get_bm25_store(pipeline)
        for variant in variants:
            try:
                hits = store.search(variant, top_k=top_k, document=file_name)
            except Exception as exc:
                print(f"[retrieval] BM25 skip {pipeline}: {exc}")
                break
            for hit in hits:
                chunk = hit.chunk
                key = chunk_record_key(chunk)
                cid = str(chunk.chunk_id or "")
                raw = chunk.content or ""
                if not key or not cid or not _bm25_body_usable(raw):
                    continue
                body = _strip_toc_prefix(raw)
                ct = chunk.content_type.value if chunk.content_type else ""
                doc_id = str(getattr(chunk, "document_id", None) or "")
                file_name = str(chunk.file_name or pipeline)
                item = RankedItem(
                    item_id=key,
                    rank=int(hit.rank),
                    source=f"bm25:{pipeline}",
                    score=float(hit.score),
                    payload={
                        "type": "Document",
                        "source": file_name,
                        "body": body,
                        "score": float(hit.score),
                        "structured": False,
                        "section": chunk.section or "",
                        "page": chunk.page,
                        "chunk_id": cid,
                        "document_id": doc_id,
                        "content_type": ct,
                        "parent_id": getattr(chunk, "parent_id", None),
                        "prev_chunk_id": getattr(chunk, "prev_chunk_id", None),
                        "next_chunk_id": getattr(chunk, "next_chunk_id", None),
                        "table_id": getattr(chunk, "table_id", None),
                        "toc_path": (
                            " > ".join(chunk.toc_path)
                            if isinstance(chunk.toc_path, list)
                            else (chunk.toc_path or "")
                        ),
                        "metadata": {
                            "file_name": chunk.file_name,
                            "section": chunk.section,
                            "page": chunk.page,
                            "pipeline": pipeline,
                            "content_type": ct,
                            "document_id": doc_id,
                            "parent_id": getattr(chunk, "parent_id", None),
                            "prev_chunk_id": getattr(chunk, "prev_chunk_id", None),
                            "next_chunk_id": getattr(chunk, "next_chunk_id", None),
                            "table_id": getattr(chunk, "table_id", None),
                        },
                        "pipeline": pipeline,
                    },
                )
                prev = best.get(key)
                if prev is None or int(hit.rank) < int(prev.rank) or (
                    int(hit.rank) == int(prev.rank) and float(hit.score) > float(prev.score)
                ):
                    best[key] = item
    # Stable order by best rank then score for RRF list construction.
    return sorted(best.values(), key=lambda it: (it.rank, -float(it.score or 0.0)))


def _prepare_ce_pool(query: str, pool: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Demote front-matter; soft-prefer message inventories and taxonomy primary FS."""
    if not pool:
        return pool
    list_intent = is_message_list_intent(query)
    technical: list[dict[str, Any]] = []
    front: list[dict[str, Any]] = []
    weak: list[dict[str, Any]] = []
    for ev in pool:
        if is_front_matter_evidence(ev):
            front.append(ev)
        elif list_intent and is_weak_message_list_context(ev):
            weak.append(ev)
        else:
            technical.append(ev)
    if list_intent and technical:
        invent = [ev for ev in technical if is_message_inventory(ev)]
        rest = [ev for ev in technical if not is_message_inventory(ev)]
        ordered = invent + rest + weak + front
    else:
        ordered = technical + weak + front
    return _soft_prefer_primary_fs(query, ordered)


def _src_blob(ev: dict[str, Any]) -> str:
    meta = ev.get("metadata") if isinstance(ev.get("metadata"), dict) else {}
    return " ".join(
        str(x or "")
        for x in (
            ev.get("source"),
            ev.get("file_name"),
            meta.get("file_name"),
            meta.get("source"),
            ev.get("document_id"),
            meta.get("document_id"),
        )
    ).lower()


def _primary_fs_filenames(query: str) -> list[str]:
    """Enrolled file_name values that match the taxonomy primary FS doc."""
    try:
        from app.ontology.taxonomy import primary_fs_document
        from app.retrieval.document_registry import resolve_documents
    except Exception:
        return []
    primary = (primary_fs_document(query) or "").strip().upper()
    if not primary:
        return []
    names: list[str] = []
    seen: set[str] = set()
    try:
        for c in resolve_documents(query) or []:
            fn = str(getattr(c, "file_name", "") or "")
            if primary.lower() in fn.lower() and fn not in seen:
                seen.add(fn)
                names.append(fn)
    except Exception:
        pass
    # Also scan vector-store catalogs (covers duplicate / alternate filenames).
    try:
        from shared.vector_store import VectorStore

        for pipeline in ("docling", "original"):
            for fn in VectorStore(pipeline).list_documents() or []:
                if primary.lower() in str(fn).lower() and fn not in seen:
                    seen.add(fn)
                    names.append(fn)
    except Exception:
        pass
    return names


def _soft_prefer_primary_fs(query: str, pool: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Soft-rank protocol primary (FS.11 for SS7) ahead of demoted docs (FS.19)."""
    if not pool:
        return pool
    try:
        from app.ontology.taxonomy import demoted_fs_documents_for_query, primary_fs_document
    except Exception:
        return pool
    primary = (primary_fs_document(query) or "").lower()
    if not primary:
        return pool
    demoted = {d.lower() for d in demoted_fs_documents_for_query(query)}

    prefer = [ev for ev in pool if primary in _src_blob(ev)]
    mid = [
        ev for ev in pool
        if ev not in prefer and not any(d in _src_blob(ev) for d in demoted)
    ]
    demote = [ev for ev in pool if ev not in prefer and ev not in mid]
    return prefer + mid + demote


def _inject_primary_fs_survivors(
    query: str,
    ranked: list[dict[str, Any]],
    pool: list[dict[str, Any]],
    *,
    top_k: int,
) -> list[dict[str, Any]]:
    """If CE dropped primary-FS hits, pull them back from the pool."""
    try:
        from app.ontology.taxonomy import primary_fs_document
    except Exception:
        return ranked
    primary = (primary_fs_document(query) or "").lower()
    if not primary or top_k <= 0:
        return ranked

    primary_in_head = [ev for ev in ranked[:top_k] if primary in _src_blob(ev)]
    if len(primary_in_head) >= max(2, top_k // 2):
        return ranked

    survivors = [ev for ev in pool if primary in _src_blob(ev)]
    if not survivors:
        return ranked
    keep_n = min(max(3, top_k - 1), len(survivors))
    head = survivors[:keep_n]
    head_keys = {evidence_key(ev) for ev in head}
    rest = [ev for ev in ranked if evidence_key(ev) not in head_keys]
    return head + rest


def _finalize_primary_pack(
    query: str,
    ranked: list[dict[str, Any]],
    *,
    top_k: int,
) -> list[dict[str, Any]]:
    """When primary FS has enough hits, drop wrong-protocol demoted docs from the pack.

    SS7 “prohibited/CAT1” questions otherwise drown in FS.19 Diameter Category-1
    chunks that share the same vocabulary.
    """
    if not ranked or top_k <= 0:
        return ranked
    try:
        from app.ontology.taxonomy import demoted_fs_documents_for_query, primary_fs_document
    except Exception:
        return ranked[: max(top_k + 2, top_k)]

    primary = (primary_fs_document(query) or "").lower()
    if not primary:
        return ranked
    demoted = {d.lower() for d in demoted_fs_documents_for_query(query)}
    prefer = [ev for ev in ranked if primary in _src_blob(ev)]
    if len(prefer) < 2:
        return ranked

    mid = [
        ev for ev in ranked
        if ev not in prefer and not any(d in _src_blob(ev) for d in demoted)
    ]
    # Allow at most one demoted chunk as contrast — never let it dominate.
    demote = [ev for ev in ranked if ev not in prefer and ev not in mid][:1]
    limit = max(top_k + 2, min(len(prefer) + len(mid) + 1, max(top_k, 8)))
    return (prefer + mid + demote)[:limit]


def _blend_message_list_tables(
    query: str,
    ranked: list[dict[str, Any]],
    sparse_items: list[RankedItem],
    *,
    top_k: int,
) -> list[dict[str, Any]]:
    """Promote BM25 message inventories ahead of CE intro/scope distractors.

    Generic (inventory/table heuristics + list intent) — no opcode hardfixes.
    """
    if not is_message_list_intent(query) or top_k <= 0:
        return ranked

    ranked_by_key = {evidence_key(ev): ev for ev in ranked}
    preferred: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Prefer full TABLE chunks over TABLE_ROW fragments for list answers.
    def _inventory_rank(it: RankedItem) -> tuple:
        ct = str(it.payload.get("content_type") or "").lower()
        if ct == "table":
            kind = 0
        elif ct == "table_row":
            kind = 1
        elif is_message_inventory(it.payload):
            kind = 2
        else:
            kind = 9
        return (kind, it.rank, -float(it.score or 0))

    sparse_inventory = sorted(
        (it for it in sparse_items if is_message_inventory(it.payload)),
        key=_inventory_rank,
    )

    # 1) BM25-ranked inventories first (full tables → rows → inventory prose).
    reserve = max(3, min(6, top_k))
    for it in sparse_inventory:
        if len(preferred) >= reserve:
            break
        ev = it.payload
        key = evidence_key(ev)
        if key in seen:
            continue
        row = dict(ranked_by_key.get(key) or ev)
        row["_bm25_inventory_promote"] = True
        preferred.append(row)
        seen.add(key)

    # 2) Remaining CE hits that are inventories but were not in BM25 head.
    for ev in ranked:
        key = evidence_key(ev)
        if key in seen:
            continue
        if is_message_inventory(ev) and not is_weak_message_list_context(ev):
            preferred.append(ev)
            seen.add(key)
            if len(preferred) >= reserve:
                break

    # 3) Fill with other CE hits (skip weak intro/scope until needed).
    strong_rest: list[dict[str, Any]] = []
    weak_rest: list[dict[str, Any]] = []
    for ev in ranked:
        key = evidence_key(ev)
        if key in seen:
            continue
        if is_weak_message_list_context(ev):
            weak_rest.append(ev)
        else:
            strong_rest.append(ev)

    out = preferred + strong_rest + weak_rest
    return out[:top_k]


def _section_key(ev: dict[str, Any]) -> str:
    src = str(ev.get("source") or "")
    sec = str(ev.get("section") or "").split("|")[0].strip().lower()
    return f"{src}||{sec}"


def pure_qdrant_search(
    query: str,
    *,
    top_k: int = 20,
    filters: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Dense cosine (wide) + BM25 lexical → CE top_k for the generator.

    Diagram target is ~30 candidates into the reranker. With tightly clustered
    instruct-embed scores we keep a wider dense over-fetch so definitions that
    sit deeper in cosine still reach Qwen3-Reranker / MiniLM.
    """
    from app.config.settings import settings
    from app.retrieval.cross_encoder import rerank_with_cross_encoder

    filters = dict(filters or {})
    hard: dict[str, Any] = {}
    scope_file: str | None = None
    if filters.get("file_name") and filters.get("_user_document_scope"):
        hard["file_name"] = filters["file_name"]
        hard["_hard_scope"] = True
        scope_file = str(filters["file_name"])
    elif filters.get("file_names") and filters.get("_user_document_scope"):
        hard["file_names"] = filters["file_names"]
        hard["_hard_scope"] = True

    candidate_k = max(int(getattr(settings, "candidate_pool_k", 30) or 30), top_k)
    # Wide dense pool — instruct-embed cosine ranks stay tightly clustered, so
    # definitions that sit deeper still reach the cross-encoder.
    dense_k = max(candidate_k * 4, int(settings.cross_encoder_pool_k or 400), 200)
    bm25_k = max(candidate_k * 2, 60)

    store = get_qdrant_store()
    dense_hits = store.search_cosine_only(query, top_k=dense_k, filters=hard or None)

    # Taxonomy primary FS leg — SS7/Diameter/GTP questions often drown in the
    # wrong FS.* “Category N” chapters unless we over-fetch from the primary doc.
    primary_files = [] if hard else _primary_fs_filenames(query)
    if primary_files:
        primary_k = max(40, min(120, dense_k // 2))
        primary_filters = {
            "_hard_scope": True,
            "file_names": primary_files,
        }
        if len(primary_files) == 1:
            primary_filters = {"_hard_scope": True, "file_name": primary_files[0]}
        try:
            primary_hits = store.search_cosine_only(
                query, top_k=primary_k, filters=primary_filters
            )
        except Exception as exc:
            print(f"[retrieval] primary-FS dense leg skipped: {exc}")
            primary_hits = []
        # Prepend unique primary hits so they enter RRF/CE even if global dense missed them.
        seen_ids = {
            str(h.get("chunk_id") or (h.get("payload") or {}).get("chunk_id") or "")
            for h in dense_hits
        }
        merged: list[dict[str, Any]] = []
        for h in primary_hits:
            cid = str(h.get("chunk_id") or (h.get("payload") or {}).get("chunk_id") or "")
            if cid and cid in seen_ids:
                continue
            if cid:
                seen_ids.add(cid)
            merged.append(h)
        dense_hits = merged + list(dense_hits)

    dense_items: list[RankedItem] = []
    dense_by_section: dict[str, dict[str, Any]] = {}
    for rank, h in enumerate(dense_hits, start=1):
        ev = _hit_to_evidence(h)
        key = evidence_key(ev) or f"dense-{rank}"
        dense_items.append(
            RankedItem(
                item_id=key,
                rank=rank,
                source="qdrant:dense",
                score=float(ev.get("score") or 0.0),
                payload=ev,
            )
        )
        sk = _section_key(ev)
        if sk not in dense_by_section:
            dense_by_section[sk] = ev

    # BM25: global + primary-FS scoped (when taxonomy has a protocol primary).
    sparse_items = _bm25_leg(query, top_k=bm25_k, file_name=scope_file)
    if primary_files and not scope_file:
        primary_sparse: list[RankedItem] = []
        for fn in primary_files[:3]:
            primary_sparse.extend(_bm25_leg(query, top_k=max(30, bm25_k // 2), file_name=fn))
        # Dedupe by evidence key, keep best rank.
        by_key: dict[str, RankedItem] = {}
        for it in list(primary_sparse) + list(sparse_items):
            k = evidence_key(it.payload) or it.item_id
            prev = by_key.get(k)
            if prev is None or int(it.rank) < int(prev.rank):
                by_key[k] = it
        sparse_items = sorted(by_key.values(), key=lambda it: (it.rank, -float(it.score or 0)))
    # Prefer real Qdrant prose when BM25 matched the same section — but never
    # overwrite a command/message table with longer neighboring prose.
    for it in sparse_items:
        if is_table_like(it.payload) or is_message_inventory(it.payload):
            continue
        sk = _section_key(it.payload)
        dense_ev = dense_by_section.get(sk)
        if dense_ev and len(str(dense_ev.get("body") or "")) > len(str(it.payload.get("body") or "")):
            it.payload["body"] = dense_ev["body"]
            it.payload["chunk_id"] = dense_ev.get("chunk_id") or it.payload.get("chunk_id")
            it.payload["document_id"] = dense_ev.get("document_id") or it.payload.get("document_id")
            it.payload["page"] = dense_ev.get("page")
            it.payload["metadata"] = dense_ev.get("metadata") or it.payload.get("metadata")

    sparse_w = sparse_rrf_weight(query)
    # Message-list NL questions are sparse-heavy: dense rarely hits command tables.
    if is_message_list_intent(query):
        sparse_w = max(sparse_w, 2.0)
    lists = [lst for lst in (dense_items, sparse_items) if lst]
    weights = []
    for lst in lists:
        if lst and str(lst[0].source).startswith("qdrant"):
            weights.append(1.0)
        else:
            weights.append(sparse_w)

    if lists:
        fused = reciprocal_rank_fusion(
            lists,
            k=int(settings.rrf_k or 60),
            top_k=max(candidate_k, 1),
            list_weights=weights,
        )
        fused_ev = [item.to_evidence() for item in fused]
    else:
        fused_ev = []

    # Always keep a deep dense head in the CE pool so RRF can't bury rare defs.
    # Also keep a BM25 head so lexical table hits survive dense-dominated fusion.
    ce_pool: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    bm25_head = [it.payload for it in sparse_items[: max(candidate_k, 40)]]
    for ev in fused_ev + bm25_head + [it.payload for it in dense_items[:dense_k]]:
        key = evidence_key(ev) or _section_key(ev)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        ce_pool.append(ev)
        if len(ce_pool) >= max(candidate_k, min(dense_k, 400)):
            break

    ce_pool = _prepare_ce_pool(query, ce_pool)
    evidence = _merge_same_section_siblings(ce_pool)
    backend = "qdrant_cosine+bm25" if sparse_items else "qdrant_cosine"
    fusion = "rrf+dense_head" if sparse_items else "dense"

    if settings.use_cross_encoder and evidence:
        try:
            # Message-list tables often score a bit below TOC/overview distractors;
            # widen the CE margin so the gold table is not gap-filtered away.
            ce_margin = float(settings.cross_encoder_score_margin)
            if is_message_list_intent(query):
                ce_margin = max(ce_margin, 2.5)
            ranked = rerank_with_cross_encoder(
                query,
                evidence,
                model_name=settings.cross_encoder_model,
                top_k=max(top_k * 2, top_k),
                score_margin=ce_margin,
            )
            ranked = _blend_message_list_tables(
                query, ranked, sparse_items, top_k=top_k
            )
            # Ensure Diameter→FS.19 / SS7→FS.11 survives CE when present in the pool.
            ranked = _inject_primary_fs_survivors(query, ranked, evidence, top_k=top_k)
            ranked = _soft_prefer_primary_fs(query, ranked)
            ranked = _expand_final_evidence(ranked)
            ranked = _finalize_primary_pack(query, ranked, top_k=top_k)
            ranked = _cap_evidence(ranked, top_k=top_k)
            return {
                "results": ranked,
                "evidence": ranked,
                "backend": f"{backend}+ce",
                "fusion": fusion,
                "candidate_k": len(evidence),
            }
        except Exception as exc:
            print(f"[retrieval] pure-path CE skipped: {exc}")

    final = _blend_message_list_tables(
        query, evidence[: max(top_k * 2, top_k)], sparse_items, top_k=top_k
    )
    final = _inject_primary_fs_survivors(query, final, evidence, top_k=top_k)
    final = _soft_prefer_primary_fs(query, final)
    final = _expand_final_evidence(final)
    final = _finalize_primary_pack(query, final, top_k=top_k)
    final = _cap_evidence(final, top_k=top_k)
    return {
        "results": final,
        "evidence": final,
        "backend": backend,
        "fusion": fusion,
        "candidate_k": len(evidence),
    }


def _cap_evidence(evidence: list[dict[str, Any]], *, top_k: int) -> list[dict[str, Any]]:
    """Keep promoted head + limited expansion; drop front-matter fillers."""
    if not evidence:
        return evidence
    cleaned = [ev for ev in evidence if not is_front_matter_evidence(ev)]
    if not cleaned:
        cleaned = list(evidence)
    # Allow a few expansion neighbors beyond top_k (parent table, heading).
    limit = max(top_k + 2, min(len(cleaned), max(top_k, 8)))
    return cleaned[:limit]


def _expand_final_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parent / prev / next / TABLE expansion with dedupe + char cap."""
    try:
        from app.retrieval.context_expand import expand_evidence_list

        return expand_evidence_list(evidence)
    except Exception as exc:
        print(f"[retrieval] context expand skipped: {exc}")
        return evidence
