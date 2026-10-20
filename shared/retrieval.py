"""Retrieval with parent-child, TOC, and neighbor context assembly."""

from __future__ import annotations

from typing import List, Optional

import config
from docling_pipeline.table_serializer import serialize_table_markdown
from shared.schema import ChunkRecord, ContentType, RetrievalResult
from shared.vector_store import VectorStore


def _analyze_query(query: str, available_docs: List[str]) -> dict:
    """Resolve optional target document from the query (filename match or LLM)."""
    from shared.llm import is_llm_available

    if not available_docs:
        return {"document": None, "keywords": query, "refined_query": query}

    import re

    # Filename token overlap (no domain keyword maps)
    query_compact = query.lower().replace(".", "").replace(" ", "").replace("_", "").replace("-", "")
    query_tokens = {t for t in re.split(r"\W+", query.lower()) if len(t) >= 3}
    for doc in available_docs:
        doc_lower = doc.lower()
        name_parts = [
            p for p in re.split(r"[^a-z0-9]+", doc_lower) if len(p) >= 4
        ]
        for part in name_parts:
            if part.replace(".", "") in query_compact:
                return {"document": doc, "keywords": query, "refined_query": query}

    # Only ask the LLM when the query already shares a filename token (avoids guessing)
    name_overlap = False
    for doc in available_docs:
        parts = {p for p in re.split(r"[^a-z0-9]+", doc.lower()) if len(p) >= 4}
        if query_tokens & parts:
            name_overlap = True
            break

    if is_llm_available() and len(available_docs) > 1 and name_overlap:
        try:
            from shared.llm import answer_question_raw

            doc_list = "\n".join(f"- {d}" for d in available_docs)
            analysis_prompt = (
                f"Available documents:\n{doc_list}\n\n"
                f"User query: \"{query}\"\n\n"
                "Which document filename (if any) is this question about? "
                "Reply with ONLY the exact filename, or ALL if unclear. No explanation."
            )
            result = answer_question_raw(analysis_prompt, max_tokens=60)
            result = result.strip().strip('"').strip("'")
            if result.upper() == "ALL":
                return {"document": None, "keywords": query, "refined_query": query}
            for doc in available_docs:
                if result.lower() in doc.lower() or doc.lower() in result.lower():
                    return {"document": doc, "keywords": query, "refined_query": query}
        except Exception:
            pass

    return {"document": None, "keywords": query, "refined_query": query}


def retrieve(
    query: str,
    pipeline: str,
    top_k: Optional[int] = None,
    document: Optional[str] = None,
    *,
    sparse_only: bool = False,
) -> List[RetrievalResult]:
    """Dense (Qdrant) + sparse (TF-IDF + BM25) fused with RRF."""
    from shared.bm25_store import get_bm25_store, reciprocal_rank_fusion
    from shared.tfidf_store import get_tfidf_store

    store = VectorStore(pipeline)
    if not document:
        analysis = _analyze_query(query, store.list_documents())
        document = analysis.get("document")

    k = top_k or config.TOP_K
    pool = max(k * 3, 12)

    dense_hits: List[RetrievalResult] = []
    if not sparse_only:
        dense_hits = store.search(query, top_k=pool, document=document)
        min_score = float(getattr(config, "RETRIEVAL_MIN_SCORE", 0.0) or 0.0)
        if min_score > 0 and dense_hits:
            dense_hits = [h for h in dense_hits if float(h.score) >= min_score]

    if not store._chunks:
        try:
            store.load()
        except FileNotFoundError:
            pass

    sparse_lists: list[list[RetrievalResult]] = []
    try:
        bm25 = get_bm25_store(pipeline)
        bm25.ensure_ready(store._chunks)
        sparse_lists.append(bm25.search(query, top_k=pool, document=document))
    except Exception:
        pass
    try:
        tfidf = get_tfidf_store(pipeline)
        tfidf.ensure_ready(store._chunks)
        sparse_lists.append(tfidf.search(query, top_k=pool, document=document))
    except Exception:
        pass

    ranked_lists: list[list[RetrievalResult]] = []
    if dense_hits:
        ranked_lists.append(dense_hits)
    ranked_lists.extend(lst for lst in sparse_lists if lst)

    sparse_w = 1.0
    try:
        from app.retrieval.post_fusion import sparse_rrf_weight

        sparse_w = sparse_rrf_weight(query)
    except Exception:
        pass
    weights: list[float] = []
    if dense_hits:
        weights.append(1.0)
    for _ in sparse_lists:
        weights.append(sparse_w)

    rrf_k = int(getattr(config, "RRF_K", 60) or 60)
    if len(ranked_lists) > 1:
        hits = reciprocal_rank_fusion(ranked_lists, k=rrf_k, top_k=k, list_weights=weights)
    elif ranked_lists:
        hits = ranked_lists[0][:k]
    else:
        hits = []

    # RRF scores are rank-based (not cosine); min_score applies to dense leg only.

    if pipeline == "docling":
        if not store._chunks:
            try:
                store.load()
            except FileNotFoundError:
                pass
        hits = _expand_hits(store, hits, query)
    return hits


def _expand_hits(
    store: VectorStore,
    hits: List[RetrievalResult],
    query: str,
) -> List[RetrievalResult]:
    """Recover parent table/section, neighbors, and TOC so mid-document context is not lost."""
    if not hits:
        return hits
    if store._chunks is None or not store._chunks:
        store.load()

    by_id = {c.chunk_id: c for c in store._chunks}
    seen = {h.chunk.chunk_id for h in hits}
    extras: List[RetrievalResult] = []

    def _add(chunk: Optional[ChunkRecord], score: float) -> None:
        if not chunk or chunk.chunk_id in seen:
            return
        seen.add(chunk.chunk_id)
        extras.append(RetrievalResult(chunk=chunk, score=score, rank=len(hits) + len(extras) + 1))

    structure_query = any(
        w in query.lower()
        for w in ("section", "table of contents", "toc", "outline", "chapter", "heading")
    )
    if structure_query:
        # Only add TOC from the same document as top hit
        top_file = hits[0].chunk.file_name if hits else None
        for c in store._chunks:
            if c.content_type == ContentType.TOC and c.file_name == top_file:
                _add(c, hits[0].score)
                break

    for h in hits:
        chunk = h.chunk
        for parent in store.get_parent_chain(chunk):
            _add(parent, h.score * 0.92)
        _add(by_id.get(chunk.prev_chunk_id or ""), h.score * 0.85)
        _add(by_id.get(chunk.next_chunk_id or ""), h.score * 0.85)
        if chunk.content_type == ContentType.TABLE_ROW and chunk.parent_id:
            _add(by_id.get(chunk.parent_id), h.score * 0.95)

    combined = list(hits) + extras
    combined.sort(key=lambda r: r.score, reverse=True)
    for i, r in enumerate(combined, start=1):
        r.rank = i
    return combined


def assemble_context(
    results: List[RetrievalResult],
    pipeline: str,
    include_parents: bool = True,
) -> str:
    store = VectorStore(pipeline)
    if not store._chunks:
        try:
            store.load()
        except FileNotFoundError:
            return ""
    blocks: List[str] = []
    seen: set[str] = set()

    # Sort results: group by primary document (most hits) first
    if results:
        from collections import Counter
        doc_counts = Counter(r.chunk.file_name for r in results if r.chunk.file_name)
        primary_doc = doc_counts.most_common(1)[0][0] if doc_counts else None
        # Re-sort: primary doc chunks first, then others
        results = sorted(results, key=lambda r: (
            0 if r.chunk.file_name == primary_doc else 1,
            -r.score,
        ))

    # Only show TOC if it's from the primary document
    if pipeline == "docling" and results:
        primary_file = results[0].chunk.file_name
        toc = next(
            (c for c in (store._chunks or [])
             if c.content_type == ContentType.TOC and c.file_name == primary_file),
            None,
        )
        if toc:
            outline = "\n".join(toc.content.strip().splitlines()[:20])
            blocks.append(f"---\nDocument outline ({primary_file})\n{outline}")

    primary_file = results[0].chunk.file_name if results else None
    secondary_count = 0
    max_secondary = 3  # limit noise from non-primary docs

    for r in results:
        chunk = r.chunk
        if chunk.chunk_id in seen:
            continue

        # Limit chunks from non-primary documents to reduce noise
        if chunk.file_name and chunk.file_name != primary_file:
            secondary_count += 1
            if secondary_count > max_secondary:
                continue

        seen.add(chunk.chunk_id)
        parts: List[str] = []

        if include_parents:
            for parent in store.get_parent_chain(chunk):
                if parent.chunk_id in seen:
                    continue
                seen.add(parent.chunk_id)
                if parent.content_type == ContentType.HEADING:
                    parts.append(f"[Section] {parent.toc_path or parent.section}\n{parent.content[:800]}")

        if chunk.content_type == ContentType.TABLE_ROW and chunk.structured_table:
            parts.append(_format_table_row_block(chunk))
        elif chunk.content_type == ContentType.TABLE and chunk.structured_table:
            parts.append(_format_table_block(chunk))
        elif chunk.content_type == ContentType.TOC:
            continue
        else:
            parts.append(chunk.content[:1200])

        # Include neighboring chunks for fuller context (avoids broken passages)
        for neighbor in store.get_neighbors(chunk):
            if neighbor.chunk_id in seen:
                continue
            if neighbor.content_type in (ContentType.PARAGRAPH, ContentType.TEXT, ContentType.LIST_ITEM):
                seen.add(neighbor.chunk_id)
                parts.append(f"[Adjacent context]\n{neighbor.content[:600]}")

        if not parts:
            continue
        citation = _citation(chunk)
        blocks.append(f"---\nScore: {r.score:.4f} | {citation}\n" + "\n".join(parts))

    context = "\n\n".join(blocks)
    if len(context) > config.CONTEXT_MAX_CHARS:
        context = context[: config.CONTEXT_MAX_CHARS] + "\n\n[context truncated]"
    return context


def _citation(chunk: ChunkRecord) -> str:
    parts = [f"chunk:{chunk.chunk_id}"]
    if chunk.toc_path:
        parts.append(f"toc:{chunk.toc_path}")
    elif chunk.section:
        parts.append(f"section:{chunk.section}")
    if chunk.table_id:
        parts.append(f"table:{chunk.table_id}")
    if chunk.page:
        parts.append(f"page:{chunk.page}")
    return " | ".join(parts)


def _format_table_block(chunk: ChunkRecord) -> str:
    tbl = chunk.structured_table
    if not tbl:
        return chunk.content
    header = f"Source: {chunk.toc_path or chunk.section}"
    if tbl.caption:
        header += f" → {tbl.caption}"
    if chunk.page:
        header += f" (Page {chunk.page})"
    md = serialize_table_markdown(tbl, max_rows=8)
    return f"{header}\n\n{md}"


def _format_table_row_block(chunk: ChunkRecord) -> str:
    tbl = chunk.structured_table
    if not tbl:
        return chunk.content
    header = f"Source: {chunk.toc_path or chunk.section}"
    if tbl.caption:
        header += f" → {tbl.caption}"
    if chunk.page:
        header += f" → Page {chunk.page}"
    return f"{header}\n\nMatched row:\n{chunk.content}"
