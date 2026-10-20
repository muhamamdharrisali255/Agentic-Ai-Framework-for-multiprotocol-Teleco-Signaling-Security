"""Hybrid RAG: structured SQL + entity graph + dense/BM25 vector retrieval."""

from __future__ import annotations

from typing import Optional

import config
from shared.neo4j_store import get_graph_store
from shared.mongo_store import get_structured_store
from shared.retrieval import assemble_context, retrieve
from shared.schema import RetrievalResult


def hybrid_retrieve(
    query: str,
    pipeline: str,
    top_k: Optional[int] = None,
    document: Optional[str] = None,
    search_query: Optional[str] = None,
) -> dict:
    """
    Fuse evidence layers and let the LLM answer from them:
      1) structured SQL facts/endpoints
      2) entity graph neighborhood (kept small)
      3) FAISS dense + BM25 sparse chunks (RRF)

    `query` is the user question (for answering).
    `search_query` is an optional rewritten query used only for retrieval.
    """
    k = top_k or config.TOP_K
    sq = (search_query or query).strip() or query
    # Structured/graph matching uses the original question (rewrite is for vectors only).
    fact_q = (query or "").strip() or sq

    facts: dict = {"endpoints": [], "fields": [], "documents": []}
    facts_md = ""
    strong_facts = False
    fact_docs: list[str] = []
    try:
        store = get_structured_store()
        facts = store.search_facts(fact_q, file_name=document, limit=12)
        facts_md = store.facts_markdown(fact_q, file_name=document, limit=12)
        fact_docs, strong_facts = _fact_document_hints(facts)
    except Exception as exc:
        print(f"[hybrid] structured store unavailable: {exc}")

    graph_md = ""
    try:
        graph = get_graph_store()
        if not strong_facts:
            graph_md = graph.graph_markdown(fact_q, file_name=document, limit=8)
        else:
            graph_md = graph.graph_markdown(fact_q, file_name=document, limit=3)
    except Exception as exc:
        print(f"[hybrid] graph store unavailable: {exc}")

    vec_document = document
    if not vec_document and strong_facts and fact_docs:
        vec_document = fact_docs[0]

    # Lexical boost from structured hits (roles, keys, values) — domain-agnostic.
    vec_q = sq
    if strong_facts:
        extras: list[str] = []
        for ep in (facts.get("endpoints") or [])[:6]:
            for key in ("role", "node_type", "gt_address", "fqdn", "ip"):
                val = (ep.get(key) or "").strip()
                if val and val.lower() not in vec_q.lower():
                    extras.append(val)
        for f in (facts.get("fields") or [])[:4]:
            for key in ("field_key", "field_value"):
                val = (f.get(key) or "").strip()
                if val and len(val) < 40 and val.lower() not in vec_q.lower():
                    extras.append(val)
        if extras:
            vec_q = f"{sq} {' '.join(extras[:12])}"

    # Fewer vector hits when facts are strong — evidence only, not answer fuel
    vec_k = min(k, 4) if strong_facts else k
    hits: list[RetrievalResult] = retrieve(vec_q, pipeline, top_k=vec_k, document=vec_document)
    if strong_facts and fact_docs and not document:
        scoped = [h for h in hits if (h.chunk.file_name or "") in set(fact_docs)]
        if scoped:
            hits = scoped
        hits = _rerank_hits_with_facts(hits, facts)
        hits = hits[: max(vec_k, 4)]

    vector_md = assemble_context(hits, pipeline)

    blocks: list[str] = []
    if facts_md:
        blocks.append(
            "[STRUCTURED_FACTS]\n"
            "These rows are the primary answer source. "
            "Report only values that match the user question.\n"
            + facts_md
        )
    if graph_md and not strong_facts:
        blocks.append(
            "[ENTITY_GRAPH]\n"
            "Optional relationship hints — include only if the question needs them.\n"
            + graph_md
        )
    if vector_md:
        blocks.append(
            "[RETRIEVED_CHUNKS]\n"
            "Supporting evidence only — do not dump into the answer.\n"
            + vector_md
        )

    context = "\n\n".join(blocks)
    max_chars = config.CONTEXT_MAX_CHARS + 1500
    if len(context) > max_chars:
        context = context[:max_chars] + "\n\n[context truncated]"

    meta = {
        "intent": {"mode": "hybrid+bm25"},
        "structured_backend": store.backend,
        "graph_backend": graph.backend,
        "has_facts": bool(facts_md),
        "has_graph": bool(graph_md),
        "vector_hits": len(hits),
        "document": document,
        "vector_document": vec_document,
        "fact_sources": fact_docs,
        "strong_facts": strong_facts,
        "retrieval": "faiss+bm25-rrf",
        "search_query": sq,
    }
    return {"hits": hits, "context": context, "meta": meta}


def _fact_document_hints(facts: dict) -> tuple[list[str], bool]:
    """Return (ordered fact file names, whether structured matches are strong)."""
    scores: dict[str, float] = {}
    strong = False
    for ep in facts.get("endpoints") or []:
        fn = ep.get("file_name")
        if not fn:
            continue
        sc = float(ep.get("_score") or 0)
        scores[fn] = scores.get(fn, 0.0) + sc
        if sc >= 5.0 or float(ep.get("_role_score") or 0) > 0:
            strong = True
    for field in facts.get("fields") or []:
        fn = field.get("file_name")
        if not fn:
            continue
        sc = float(field.get("_score") or 0)
        scores[fn] = scores.get(fn, 0.0) + sc * 0.5
        if sc >= 2.0 or float(field.get("_key_hits") or 0) > 0:
            strong = True
    for doc in facts.get("documents") or []:
        fn = doc.get("file_name")
        if not fn:
            continue
        sc = float(doc.get("_score") or 0)
        scores[fn] = scores.get(fn, 0.0) + sc * 0.25
        if sc >= 4.0:
            strong = True
    ordered = sorted(scores.keys(), key=lambda f: scores[f], reverse=True)
    return ordered, strong


def _rerank_hits_with_facts(hits: list[RetrievalResult], facts: dict) -> list[RetrievalResult]:
    """Boost chunks that mention values already found in structured facts."""
    if not hits:
        return hits
    needles: list[str] = []
    for ep in facts.get("endpoints") or []:
        for key in ("role", "node_type", "gt_address", "fqdn", "ip"):
            val = (ep.get(key) or "").strip()
            if len(val) >= 3:
                needles.append(val.lower())
    for f in facts.get("fields") or []:
        for key in ("field_key", "field_value"):
            val = (f.get(key) or "").strip()
            if 3 <= len(val) <= 48:
                needles.append(val.lower())
    if not needles:
        return hits

    scored: list[tuple[float, RetrievalResult]] = []
    for h in hits:
        blob = (h.chunk.content or "").lower()
        bonus = sum(1.0 for n in needles if n in blob)
        scored.append((float(h.score) + bonus * 0.02, h))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [
        RetrievalResult(chunk=h.chunk, score=h.score, rank=rank)
        for rank, (_, h) in enumerate(scored, start=1)
    ]


def hybrid_status_line(meta: dict) -> str:
    intent = meta.get("intent", {})
    return (
        f"hybrid:{intent.get('mode', 'hybrid')} · store:{meta.get('structured_backend')} · "
        f"graph:{meta.get('graph_backend')} · facts={'yes' if meta.get('has_facts') else 'no'} · "
        f"graph_hits={'yes' if meta.get('has_graph') else 'no'} · "
        f"retr={meta.get('retrieval', 'faiss')} · vec={meta.get('vector_hits', 0)}"
    )
