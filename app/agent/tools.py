"""Agent tools (implementation_plan.md §19)."""

from __future__ import annotations

from typing import Any, Optional

from app.config.settings import settings
from app.database import repositories as repo


def _allowed_file(meta: dict[str, Any], filters: dict[str, Any]) -> bool:
    fn = str(meta.get("file_name") or "")
    if filters.get("file_name") and fn != filters["file_name"]:
        return False
    names = filters.get("file_names")
    if names and fn not in names:
        return False
    return True


def _allowed_pipeline(pipe: str, filters: dict[str, Any]) -> bool:
    allowed = filters.get("pipelines")
    if allowed and pipe not in allowed:
        return False
    return True


def _apply_result_scope(results: list[dict[str, Any]], filters: dict[str, Any]) -> list[dict[str, Any]]:
    """Drop hits from wrong document/pipeline after Qdrant+FAISS merge."""
    if not filters:
        return results
    out: list[dict[str, Any]] = []
    for r in results:
        meta = r.get("metadata") or {}
        pipe = str(meta.get("pipeline") or meta.get("source") or "")
        if not _allowed_pipeline(pipe, filters):
            continue
        if not _allowed_file(meta, filters):
            continue
        out.append(r)
    return out


def vector_search(
    query: str,
    *,
    filters: Optional[dict[str, Any]] = None,
    top_k: int = 20,
    pipeline: str | None = None,
) -> dict[str, Any]:
    """Semantic + lexical search — delegates to unified hybrid retrieval."""
    from app.retrieval.hybrid_search import hybrid_search

    filters = dict(filters or {})
    if pipeline:
        filters["pipelines"] = [pipeline]
    return hybrid_search(query, filters=filters, top_k=top_k)


def hybrid_search_tool(
    query: str,
    *,
    filters: Optional[dict[str, Any]] = None,
    top_k: int = 20,
) -> dict[str, Any]:
    """Unified BM25 + vector + structured RRF retrieval."""
    from app.retrieval.hybrid_search import hybrid_search

    return hybrid_search(query, filters=dict(filters or {}), top_k=top_k)


def structured_facts_search(
    query: str,
    *,
    file_name: str | None = None,
    tadig: str | None = None,
    document_id: str | None = None,
    file_names: list[str] | None = None,
) -> dict[str, Any]:
    """IR.21 / Mongo structured facts relevant to the query."""
    try:
        from shared.facts_answer import formal_brief_from_facts

        answer, sources, payload = formal_brief_from_facts(
            query,
            file_name=file_name,
            tadig=tadig,
            document_id=document_id,
            file_names=file_names,
        )
        if not answer:
            return {"results": [], "backend": "structured_facts", "text": ""}
        return {
            "results": [{"text": answer, "sources": sources, "facts": payload}],
            "backend": "structured_facts",
            "text": answer,
        }
    except Exception:
        return {"results": [], "backend": "structured_facts", "text": ""}


def ir21_search(query: str, *, top_k: int = 40) -> dict[str, Any]:
    """Structured retrieval over the IR.21 relations in PostgreSQL.

    Returns one evidence item per matching row so the answer model cites a
    database record rather than a paragraph, plus the SQL that produced it.
    """
    try:
        from ir21.retrieval import evidence_markdown, operator_label, search
    except Exception:
        return {"results": [], "evidence": [], "backend": "postgresql", "queries": []}

    try:
        hits = search(query, limit=top_k)
    except Exception as exc:
        return {
            "results": [],
            "evidence": [],
            "backend": "postgresql",
            "error": str(exc),
            "queries": [],
        }

    operator = operator_label()
    evidence: list[dict[str, Any]] = []
    queries: list[dict[str, Any]] = []
    for hit in hits:
        queries.append({"table": hit.spec.table, "sql": hit.sql, "params": hit.params})
        for index, row in enumerate(hit.rows):
            page = row.get("page")
            pairs = [
                f"{col.replace('_', ' ')}: {row[col]}"
                for col in hit.spec.display_columns
                if col != "page" and str(row.get(col) or "").strip()
            ]
            trading = str(row.get("presentation_name") or "").strip()
            tadig = str(row.get("tadig") or "").strip()
            who = trading or str(row.get("organisation_name") or operator or "IR.21")
            if tadig:
                who = f"{who} ({tadig})"
            citation = f"{who} — {hit.spec.label}"
            if row.get("section_id"):
                citation += f", section {row['section_id']}"
            if page:
                citation += f", p.{page}"
            evidence.append(
                {
                    "type": "Structured Record",
                    # The operator belongs in the citation: a bare table name
                    # gives the answer model no way to tie a row to the network
                    # the question names.
                    "source": citation,
                    "section": hit.spec.label,
                    "body": "; ".join(pairs),
                    "score": float(hit.score) + 10.0,
                    "page": page,
                    "table": hit.spec.table,
                    "chunk_id": f"{hit.spec.table}:{index}",
                    "structured": True,
                    "row": row,
                }
            )

    return {
        "results": evidence,
        "evidence": evidence,
        "backend": "postgresql",
        "operator": operator,
        "queries": queries,
        "row_count": len(evidence),
        "markdown": evidence_markdown(query, hits),
    }


def sql_search(tool: str, **kwargs: Any) -> dict[str, Any]:
    if tool == "find_subscriber":
        row = repo.find_subscriber(**kwargs)
        return {"results": [row] if row else [], "backend": "postgres"}
    if tool == "find_sessions":
        return {"results": repo.find_sessions(**kwargs), "backend": "postgres"}
    if tool == "find_alerts":
        return {"results": repo.find_alerts(**kwargs), "backend": "postgres"}
    if tool == "find_attack_pattern":
        return {"results": repo.find_attack_pattern(**kwargs), "backend": "postgres"}
    if tool == "find_dictionary_term":
        row = repo.find_dictionary_term(kwargs.get("term", ""))
        return {"results": [row] if row else [], "backend": "postgres"}
    if tool == "find_operator":
        return {"results": repo.find_operator(**kwargs), "backend": "postgres"}
    return {"results": [], "backend": "postgres"}


def dictionary_search(term: str) -> dict[str, Any]:
    from app.nlp.domain_dictionary import find_term

    row = find_term(term)
    return {"results": [row] if row else [], "backend": "domain_dictionary"}


def threat_search(query: str, *, protocol: Optional[str] = None) -> dict[str, Any]:
    """Attack-pattern knowledge from the document corpus — not a second SQL store."""
    focused = f"{query} attack pattern detection indicators"
    if protocol:
        focused = f"{focused} {protocol}"
    payload = vector_search(focused, top_k=8)
    evidence = []
    for item in payload.get("evidence") or payload.get("results") or []:
        body = str(item.get("body") or item.get("text") or "")
        low = body.lower()
        if any(k in low for k in ("attack", "hijack", "threat", "abuse", "fraud", "detect", "malicious")):
            item = dict(item)
            item["type"] = "Threat Knowledge"
            evidence.append(item)
        if len(evidence) >= 5:
            break
    if not evidence:
        evidence = list(payload.get("evidence") or payload.get("results") or [])[:3]
        for item in evidence:
            item["type"] = item.get("type") or "Threat Knowledge"
    return {"results": evidence, "evidence": evidence, "backend": "vector"}


def tool_knowledge_search(query: str, *, protocol: Optional[str] = None) -> dict[str, Any]:
    """TShark / Suricata / IDS-IPS knowledge from enrolled documents."""
    focused = f"{query} Suricata detection rule TShark packet analysis IDS IPS"
    if protocol:
        focused = f"{focused} {protocol}"
    payload = vector_search(focused, top_k=6)
    evidence = list(payload.get("evidence") or payload.get("results") or [])[:4]
    for item in evidence:
        item = item  # noqa: keep original dict
        item["type"] = "Tool Knowledge"
    return {"results": evidence, "evidence": evidence, "backend": "vector"}


def table_search(
    query: str,
    *,
    limit: int = 10,
    document_id: str | None = None,
    file_name: str | None = None,
    tadig: str | None = None,
    pipelines: list[str] | None = None,
) -> dict[str, Any]:
    from app.retrieval.table_retrieval import search_tables

    rows = search_tables(
        query,
        limit=limit,
        document_id=document_id,
        file_name=file_name,
        tadig=tadig,
        pipelines=pipelines,
    )
    return {"results": rows, "backend": "postgres"}


def event_search(
    *,
    protocol: str | None = None,
    subscriber_id: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    from app.realtime.event_ingestion import list_events

    events = list_events(protocol=protocol, subscriber_id=subscriber_id, limit=limit)
    return {"results": events, "backend": "postgres"}
