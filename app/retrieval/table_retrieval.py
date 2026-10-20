"""Table-aware retrieval — delegates to unified hybrid search."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.database import postgres


def search_tables(
    query: str,
    *,
    document_id: Optional[str] = None,
    file_name: Optional[str] = None,
    tadig: Optional[str] = None,
    pipelines: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Search table/structured evidence via hybrid BM25+vector+structured RRF."""
    from app.retrieval.hybrid_search import hybrid_search

    filters: dict[str, Any] = {}
    if file_name:
        filters["file_name"] = file_name
    if tadig:
        filters["tadig"] = tadig
    if document_id:
        filters["document_id"] = document_id
    if pipelines:
        filters["pipelines"] = pipelines

    payload = hybrid_search(query, filters=filters, top_k=max(limit * 2, 12))
    rows: list[dict[str, Any]] = []
    for ev in payload.get("evidence") or []:
        if ev.get("type") not in ("Table", "Structured Facts"):
            continue
        body = str(ev.get("body") or "")
        src = str(ev.get("source") or "")
        page = None
        if " p." in src:
            try:
                page = int(src.rsplit(" p.", 1)[-1])
            except ValueError:
                page = None
        if ":" in body:
            field, _, value = body.partition(":")
            rows.append({
                "Field": field.strip(),
                "Value": value.strip(),
                "Section": ev.get("section") or "",
                "Source": src,
                "_page": page,
                "_document_id": file_name or src.split(" p.")[0],
            })
        else:
            rows.append({
                "Field": ev.get("section") or "Table",
                "Value": body[:200],
                "Section": ev.get("section") or "",
                "Source": src,
                "_page": page,
                "_document_id": file_name or "",
            })
        if len(rows) >= limit:
            return rows

    if rows:
        return rows[:limit]

    if not postgres.is_available():
        return _search_mongo_ir21_tables(
            query,
            limit=limit,
            document_id=document_id,
            file_name=file_name,
            tadig=tadig,
        )

    tokens = [t for t in query.replace(",", " ").split() if len(t) >= 3]
    q_lower = query.lower()
    sql = "SELECT table_id, document_id, page, headers, rows FROM document_tables WHERE 1=1"
    params: list[Any] = []
    if document_id:
        sql += " AND document_id = %s"
        params.append(document_id)
    sql += " LIMIT %s"
    params.append(limit * 3)
    rows_pg = postgres.fetch_all(sql, tuple(params))
    out: list[dict[str, Any]] = []
    for row in rows_pg:
        headers = row.get("headers") or []
        data_rows = row.get("rows") or []
        if isinstance(headers, str):
            headers = json.loads(headers)
        if isinstance(data_rows, str):
            data_rows = json.loads(data_rows)
        for dr in data_rows:
            if isinstance(dr, dict):
                blob = " ".join(str(v) for v in dr.values()).lower()
                if not tokens and q_lower:
                    match = True
                elif any(t.lower() in blob or t.lower() in q_lower for t in tokens):
                    match = True
                elif any(t.lower() in q_lower for t in [str(v) for v in dr.values()]):
                    match = True
                else:
                    match = False
                if match:
                    out.append({**dr, "_table_id": row["table_id"], "_page": row.get("page"), "_document_id": row["document_id"]})
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break
    return out[:limit]


def _search_mongo_ir21_tables(
    query: str,
    *,
    limit: int = 10,
    document_id: Optional[str] = None,
    file_name: Optional[str] = None,
    tadig: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Fallback: search IR.21 structured endpoints/fields as table-like rows."""
    try:
        from shared.mongo_store import get_structured_store
        from shared.postgres_store import _query_tokens, _select_facts_for_query

        store = get_structured_store()
        data = store.search_facts(
            query,
            file_name=file_name,
            document_id=document_id,
            tadig=tadig,
            limit=limit,
        )
        tokens, substantive = _query_tokens(query)
        eps, fields, _ = _select_facts_for_query(data, tokens, substantive)
        out = []
        for ep in eps:
            if ep.get("gt_address"):
                out.append({
                    "TADIG": "",
                    "Role": ep.get("role"),
                    "GT": ep.get("gt_address"),
                    "_page": ep.get("page"),
                    "_document_id": ep.get("file_name"),
                })
        for f in fields:
            if "tadig" in (f.get("field_key") or "").lower() or "operator" in (f.get("field_key") or "").lower():
                out.append({
                    "Field": f.get("field_key"),
                    "Value": f.get("field_value"),
                    "_page": f.get("page"),
                    "_document_id": f.get("file_name"),
                })
        return out[:limit]
    except Exception:
        return []


def format_table_answer(rows: list[dict[str, Any]], query: str) -> str:
    if not rows:
        return "Insufficient evidence for table lookup."
    lines = [
        "Values from structured table records.",
        "",
        "| Field | Value | Source |",
        "| :--- | :--- | :--- |",
    ]
    for row in rows[:8]:
        keys = [k for k in row if not k.startswith("_")]
        src = f"{row.get('_document_id', '')} p.{row.get('_page', '—')}"
        for key in keys:
            value = str(row.get(key, ""))
            lines.append(f"| {key} | {value} | {src} |")
    return "\n".join(lines)
