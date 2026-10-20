"""Build a formal brief answer from structured facts without calling the LLM."""

from __future__ import annotations

from typing import Any, Optional


def formal_brief_from_facts(
    query: str,
    *,
    file_name: Optional[str] = None,
    tadig: Optional[str] = None,
    document_id: Optional[str] = None,
    file_names: Optional[list[str]] = None,
    limit: int = 12,
) -> tuple[str, list[str], dict[str, Any]]:
    """
    Return (markdown_answer, source_docs, facts_payload).
    Empty answer string means facts were not strong enough.
    """
    from shared.mongo_store import get_structured_store
    from shared.postgres_store import _query_tokens, _select_facts_for_query

    try:
        store = get_structured_store()
        data = store.search_facts(
            query,
            file_name=file_name,
            tadig=tadig,
            document_id=document_id,
            file_names=file_names,
            limit=limit,
        )
    except Exception:
        return "", [], {"endpoints": [], "fields": [], "documents": []}
    tokens, substantive = _query_tokens(query)
    endpoints, fields, meta_lines = _select_facts_for_query(data, tokens, substantive)

    rows: list[tuple[str, str, str]] = []

    for ep in endpoints:
        role = (ep.get("role") or ep.get("node_type") or "Endpoint").strip()
        value = (
            ep.get("gt_address")
            or ep.get("fqdn")
            or ep.get("ip")
            or ep.get("ip_secondary")
            or ""
        ).strip()
        if not value:
            parts = [p for p in (ep.get("protocol"), ep.get("node_type")) if p and str(p).strip()]
            value = ", ".join(dict.fromkeys(parts)) if parts else "listed in IR.21"
        label = f"{role} GT" if ep.get("gt_address") else role
        bits = []
        if ep.get("section_id"):
            bits.append(f"Sec {ep['section_id']}")
        if ep.get("page"):
            bits.append(f"p.{ep['page']}")
        if ep.get("file_name"):
            bits.append(ep["file_name"])
        rows.append((label, value, ", ".join(bits)))

    for f in fields:
        key = (f.get("field_key") or "Field").strip()
        value = (f.get("field_value") or "").strip()
        if not value:
            continue
        bits = []
        if f.get("section_id"):
            bits.append(f"Sec {f['section_id']}")
        if f.get("page"):
            bits.append(f"p.{f['page']}")
        if f.get("file_name"):
            bits.append(f["file_name"])
        rows.append((key, value, ", ".join(bits)))

    covered = {r[0].lower() for r in rows}
    for line in meta_lines:
        item = value = source = ""
        try:
            body = line.lstrip("- ").strip()
            if "**" in body and "=" in body:
                item = body.split("**")[1].strip()
                rest = body.split("=", 1)[1].strip()
                if "_(" in rest:
                    value, src = rest.rsplit("_(", 1)
                    value = value.strip()
                    source = src.rstrip(")_").strip()
                else:
                    value = rest
        except Exception:
            continue
        if not (item and value):
            continue
        # Skip meta if a longer field/endpoint row already covers this label
        il = item.lower()
        if il in covered or any(il in c or c.startswith(il) for c in covered):
            continue
        rows.append((item, value, source))
        covered.add(il)

    # Deduplicate by item (keep first)
    seen: set[str] = set()
    uniq: list[tuple[str, str, str]] = []
    for item, value, source in rows:
        k = item.lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append((item, value, source))

    if not uniq:
        return "", [], data

    # Keep all rows selected by fact matching (already typo-tolerant).
    # Do not re-filter by raw substring — that drops SGSN when the query says "ssgn".

    lines = [
        "Values are derived from the structured document facts.",
        "",
        "| Item | Value | Source |",
        "| :--- | :--- | :--- |",
    ]
    for item, value, source in uniq[:12]:
        lines.append(f"| {item} | {value} | {source or '—'} |")

    sources = list(
        dict.fromkeys(
            [
                *(d.get("file_name") for d in (data.get("documents") or []) if d.get("file_name")),
                *(ep.get("file_name") for ep in endpoints if ep.get("file_name")),
                *(f.get("file_name") for f in fields if f.get("file_name")),
            ]
        )
    )
    return "\n".join(lines), sources, data
