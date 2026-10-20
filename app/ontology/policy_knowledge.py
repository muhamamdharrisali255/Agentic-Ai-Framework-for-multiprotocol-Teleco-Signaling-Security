"""Policy knowledge — retrieve message_policy rows for the LLM to reason over.

No canned answers for analyst questions: return matching structured rows only.
"""

from __future__ import annotations

import re
from typing import Any

_STOP = {
    "what", "which", "when", "where", "why", "how", "the", "a", "an", "is", "are",
    "for", "of", "to", "on", "in", "and", "or", "be", "used", "should", "normally",
    "associated", "with", "between", "difference", "parameters", "message", "messages",
    "signaling", "signalling", "relevant", "inbound", "outbound", "create", "draft",
    "generate", "detection", "rule", "unauthorized", "international", "roaming",
    "interface", "equality", "not", "sufficient", "validating", "validate", "validated",
}


def search_policy(query: str) -> dict[str, Any]:
    """Return message_policy evidence ranked by token overlap with the question."""
    q = (query or "").strip()
    tokens = _tokens(q)
    rows = _fetch_policies()
    scored: list[tuple[int, dict[str, Any]]] = []
    for row in rows:
        score = _score_row(row, tokens, q.lower())
        if score <= 0:
            continue
        scored.append((score, row))
    scored.sort(key=lambda x: (-x[0], str(x[1].get("policy_id") or "")))
    # Keep the LLM focused: top query-relevant policies only (not the whole table).
    limit = 6
    low = q.lower()
    if re.search(r"category[-\s]?([123](?:\.\d)?)\b", low) or re.search(r"\bcat[-\s]?([123](?:\.\d)?)\b", low):
        limit = 4
    evidence = [_row_evidence(row, score) for score, row in scored[:limit]]
    return {
        "evidence": evidence,
        "results": evidence,
        "backend": "message_policy",
        "empty": not evidence,
    }


def _tokens(query: str) -> list[str]:
    raw = re.findall(r"[a-z0-9][a-z0-9./_-]{1,}", (query or "").lower())
    out: list[str] = []
    for t in raw:
        if t in _STOP or len(t) < 2:
            continue
        out.append(t)
        # useful stems
        if t.endswith("s") and len(t) > 3:
            out.append(t[:-1])
    # aliases often appear as short tokens
    for alias in ("ulr", "ula", "air", "ati", "sai", "csr", "gtp", "ss7", "diameter", "cat1", "cat2", "cat3"):
        if alias in (query or "").lower().replace("-", "").replace(" ", ""):
            out.append(alias)
    if "update location" in (query or "").lower() or "updatelocation" in (query or "").lower().replace(" ", ""):
        out.extend(["updatelocation", "update", "location"])
    if "create session" in (query or "").lower():
        out.extend(["createsession", "create", "session"])
    return list(dict.fromkeys(out))


def _fetch_policies() -> list[dict[str, Any]]:
    try:
        from app.database import postgres
    except Exception:
        return []
    if not postgres.is_available():
        return []
    try:
        return postgres.fetch_all(
            """
            SELECT policy_id, direction, protocol, category, message_name,
                   validation_fields, action, signature
            FROM message_policy
            ORDER BY category, message_name
            """
        )
    except Exception:
        return []


def _score_row(row: dict[str, Any], tokens: list[str], low: str) -> int:
    blob = " ".join(str(row.get(k) or "") for k in row).lower()
    score = 0
    for t in tokens:
        if t in blob:
            score += 2 if len(t) >= 4 else 1
    cat = str(row.get("category") or "").upper()
    # Category definition / comparison questions — prefer matching CAT rows.
    m = re.search(r"category[-\s]?([123](?:\.\d)?)", low) or re.search(r"\bcat[-\s]?([123](?:\.\d)?)", low)
    if m:
        want = "CAT" + m.group(1).upper()
        if cat == want or cat.startswith(want + ".") or want.startswith(cat):
            score += 8
        elif "category-2" in low and "category-3" in low:
            if cat.startswith("CAT2") or cat.startswith("CAT3"):
                score += 5
        elif "3.1" in low and "3.2" in low:
            if cat in ("CAT3.1", "CAT3.2"):
                score += 6
        elif cat and cat not in want and not want.startswith(cat[:4]):
            score -= 2
    if "prohibit" in low and (cat == "CAT1" or "prohibit" in blob):
        score += 6
    if "ulr" in low or "update location" in low or "updatelocation" in low.replace(" ", ""):
        if "update" in blob or "ulr" in blob:
            score += 4
    if "create session" in low or "csr" in low:
        if "create" in blob or "session" in blob:
            score += 4
    if "diameter" in low and "diameter" in blob:
        score += 2
    if "gtp" in low and "gtp" in blob:
        score += 2
    if "ss7" in low and "ss7" in blob:
        score += 2
    if "validat" in low and row.get("validation_fields"):
        score += 2
    # Soft prefer checklist rows when the ASK is parameter validation.
    if re.search(r"\b(parameter|parameters|validat)", low):
        fields = str(row.get("validation_fields") or "").strip()
        if fields:
            score += 5
        else:
            score -= 4
        direction = str(row.get("direction") or "").upper()
        if "inbound" in low and direction == "INBOUND":
            score += 4
        if "outbound" in low and direction == "OUTBOUND":
            score += 4
        if cat.startswith("CAT2"):
            score += 3
        elif cat.startswith("CAT3"):
            score -= 1
    if "detection" in low and "rule" in low:
        if "ulr" in low or "update" in blob:
            score += 3
        if cat in ("CAT2", "CAT3.2"):
            score += 1
    return score


def _row_evidence(row: dict[str, Any], score: int) -> dict[str, Any]:
    fields = row.get("validation_fields") or ""
    body = (
        f"policy_id={row.get('policy_id')}; category={row.get('category')}; "
        f"protocol={row.get('protocol')}; message={row.get('message_name')}; "
        f"direction={row.get('direction')}; action={row.get('action')}"
    )
    if row.get("signature"):
        body += f"; signature={row.get('signature')}"
    if row.get("validation_type"):
        body += f"; validation_type={row.get('validation_type')}"
    if fields:
        body += f"; validation_fields={fields}"
    return {
        "type": "Message Policy",
        "source": f"policy:{row.get('policy_id')}",
        "body": body,
        "score": 3.0 + min(score, 10) * 0.05,
        "structured": True,
        "chunk_id": f"policy:{row.get('policy_id')}",
    }
