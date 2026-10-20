"""IDS rules agent — quote Suricata/IDS text; never invent signatures.

Priority:
  1. Rows from ontology `detection_rule` (cross-check with graph/attack ids)
  2. Suricata lines retrieved from tool/attack vector evidence
"""

from __future__ import annotations

import re
from typing import Any

from app.agent.parser import AgentContext
from app.ingestion.knowledge_kind import kind_of_evidence


_RULE_LINE = re.compile(
    r"(?im)^[ \t]*(alert|drop|reject|pass)\s+\S+.+$"
)
_SID = re.compile(r"\bsid\s*:\s*(\d+)", re.I)
_DETECTION = re.compile(
    r"(?i)(detection rule|suricata|signature|ids rule|monitor for|alert on)[^\n]{10,220}"
)
_PATTERN_RE = re.compile(r"\b(AP\d{3}|DR\d{3})\b", re.I)


def propose_rules(
    agent_ctx: AgentContext,
    evidence: list[dict[str, Any]],
    *,
    query: str = "",
) -> list[dict[str, Any]]:
    # Live Suricata/IPS alerts pin the exact enrolled rule (sid / rule_name).
    pinned = _from_live_alerts(agent_ctx)
    if pinned and _has_exact_sid_pin(agent_ctx, pinned):
        return pinned[:3]

    tool_howto = _looks_like_tool_howto(query)
    alert_blob = " ".join(agent_ctx.ids_alerts) + " " + " ".join(agent_ctx.observations)
    augmented_query = f"{query} {alert_blob}".strip()
    table_rules = [] if tool_howto else _from_detection_table(augmented_query, evidence)
    if table_rules:
        ranked = _merge_pinned(pinned, _rank_rules_for_query(augmented_query, table_rules))
        return ranked[:5]

    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in evidence:
        body = str(item.get("body") or item.get("text") or "")
        source = str(item.get("source") or "")
        kind = kind_of_evidence(item)
        if (
            kind not in ("tool", "attack")
            and item.get("type") not in ("IDS", "Graph Fact", "Threat Knowledge", "Tool Knowledge")
            and "suricata" not in body.lower()
            and "sid:" not in body.lower()
        ):
            continue
        for m in _RULE_LINE.finditer(body):
            text = m.group(0).strip()
            if text.lower() in seen:
                continue
            seen.add(text.lower())
            sid = _SID.search(text)
            rules.append(
                {
                    "rule": text[:500],
                    "sid": sid.group(1) if sid else "",
                    "source": source,
                    "grounded": True,
                    "from": "vector",
                }
            )
        if not _RULE_LINE.search(body):
            for m in _DETECTION.finditer(body):
                text = " ".join(m.group(0).split())
                if text.lower() in seen:
                    continue
                seen.add(text.lower())
                rules.append(
                    {
                        "rule": text[:400],
                        "sid": "",
                        "source": source,
                        "grounded": True,
                        "from": "vector",
                    }
                )
        if len(rules) >= 5:
            break

    if rules:
        return _merge_pinned(pinned, _rank_rules_for_query(augmented_query, rules))[:5]

    # Live IPS with no enrolled / retrieved rule → compose from message_policy + observation.
    if agent_ctx.has_observation and not _has_exact_sid_pin(agent_ctx, pinned):
        composed = _compose_from_ips(agent_ctx, query=query)
        if composed:
            return composed

    if agent_ctx.has_observation:
        proto = agent_ctx.protocol or "signalling"
        return [
            {
                "rule": "",
                "sid": "",
                "source": "",
                "grounded": False,
                "note": (
                    f"No IDS/Suricata signature was retrieved for this {proto} observation. "
                    "Enroll tool/attack documents or seed detection_rule, then re-run."
                ),
            }
        ]
    return []


def _compose_from_ips(agent_ctx: AgentContext, *, query: str = "") -> list[dict[str, Any]]:
    from app.agent.rule_composer import compose_rules_from_ips

    return compose_rules_from_ips(agent_ctx, query=query)


def _looks_like_tool_howto(query: str) -> bool:
    low = (query or "").lower()
    return any(
        k in low
        for k in (
            "tshark", "wireshark", "gtp_type", "preprocessor", "bpf",
            "how do i filter", "what gtp ports", "cmd.code", "display filter",
        )
    )


def _rank_rules_for_query(query: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    q = (query or "").lower()
    qtoks = [t for t in re.findall(r"[a-z0-9][a-z0-9._-]{2,}", q) if len(t) >= 3]

    def score(rule: dict[str, Any]) -> float:
        blob = " ".join(
            str(rule.get(k) or "")
            for k in ("summary", "rule", "detection_rule_id", "attack_pattern_id", "source", "sid")
        ).lower()
        s = 0.0
        for t in qtoks:
            if t in blob:
                s += 1.0
        for m in re.finditer(r"\b(ap\d{3}|dr\d{3})\b", q):
            if m.group(1) in blob:
                s += 6.0
        for m in re.finditer(r"\b(tel-[a-z0-9._-]+)\b", q):
            if m.group(1) in blob:
                s += 8.0
        if "apn" in q and "apn" in blob:
            s += 4.0
        if "routing" in q and "routing" in blob:
            s += 3.0
        q_compact = q.replace(" ", "").replace("-", "")
        blob_compact = blob.replace(" ", "").replace("-", "")
        rname = str(rule.get("summary") or rule.get("rule") or "").lower()
        if "ulr" in q or "updatelocation" in q_compact:
            if re.search(r"rule_name=[^;]*ulr", rname) or "-ulr-" in rname.replace("_", "-"):
                s += 24.0
            elif "ulr" in rname or "updatelocation" in rname.replace("-", ""):
                s += 16.0
            elif "ulr" in blob_compact:
                s += 8.0
            if "diameter" in q and "diameter" in blob and "ulr" in rname:
                s += 8.0
            if "→ulr" in blob or "->ulr" in blob or "air→ulr" in blob.lower():
                s -= 12.0
            if "roaming-abuse" in rname or "roaming_abuse" in rname:
                s -= 10.0
            if re.search(r"\bair\b", rname) and "ulr" not in rname:
                s -= 8.0
        if "air" in q and "vector" in q:
            if "air" in blob and "ulr" not in blob:
                s += 6.0
            if "ulr" in blob and "air" not in q:
                s -= 4.0
        if "hijack" in q and ("gtp" in blob or "session" in blob):
            s += 2.0
        conf = rule.get("confidence")
        if conf is not None:
            try:
                s += float(conf) * 0.01
            except (TypeError, ValueError):
                pass
        return s

    return sorted(rules, key=score, reverse=True)


def _alert_tokens(agent_ctx: AgentContext) -> tuple[list[str], list[str]]:
    """Extract Suricata SIDs and TEL-* rule names from live IPS context."""
    sids: list[str] = []
    rule_names: list[str] = []
    blob_parts = list(agent_ctx.ids_alerts) + list(agent_ctx.observations)
    for item in blob_parts:
        text = str(item or "").strip()
        if not text:
            continue
        for m in re.finditer(r"sid\s*:\s*(\d+)", text, re.I):
            sids.append(m.group(1))
        if text.isdigit() and len(text) >= 5:
            sids.append(text)
        name_m = re.search(r"\b(TEL-[A-Z0-9][A-Z0-9._-]{6,})\b", text, re.I)
        if name_m:
            rule_names.append(name_m.group(1))
    return list(dict.fromkeys(sids)), list(dict.fromkeys(rule_names))


def _has_exact_sid_pin(agent_ctx: AgentContext, pinned: list[dict[str, Any]]) -> bool:
    sids, _ = _alert_tokens(agent_ctx)
    if not sids:
        return False
    pinned_sids = {str(r.get("sid") or "") for r in pinned}
    return any(s in pinned_sids for s in sids)


def _merge_pinned(
    pinned: list[dict[str, Any]], ranked: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for rule in pinned + ranked:
        key = str(
            rule.get("detection_rule_id") or rule.get("sid") or rule.get("rule") or ""
        ).lower()
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        out.append(rule)
    return out


def _from_live_alerts(agent_ctx: AgentContext) -> list[dict[str, Any]]:
    """Resolve enrolled detection_rule rows from fired IPS/IDS alert context."""
    sids, rule_names = _alert_tokens(agent_ctx)
    if not sids and not rule_names:
        return []

    try:
        from app.database import postgres
        from app.ontology.suricata_compiler import compile_rule
    except Exception:
        return []
    if not postgres.is_available():
        return []

    clauses: list[str] = []
    params: list[Any] = []
    if sids:
        for sid in sids:
            clauses.append("COALESCE(suricata_text,'') LIKE %s")
            params.append(f"%sid:{sid}%")
    for name in rule_names:
        clauses.append("lower(rule_name) = lower(%s)")
        params.append(name)
        clauses.append("lower(rule_name) LIKE lower(%s)")
        params.append(f"%{name}%")

    sql = f"""
        SELECT detection_rule_id, attack_pattern_id, rule_name, protocol, category,
               action, confidence, status, suricata_text, severity,
               required_fields, rule_logic, detection_scope
        FROM detection_rule
        WHERE status IN ('PRODUCTION', 'TESTING')
          AND ({' OR '.join(clauses)})
        ORDER BY confidence DESC NULLS LAST
        LIMIT 3
    """
    try:
        rows = postgres.fetch_all(sql, tuple(params))
    except Exception:
        return []
    return _rows_to_rules(rows, compile_rule)


def _rows_to_rules(rows: list[dict[str, Any]], compile_rule) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        compiled = compile_rule(dict(row))
        text = compiled.get("suricata_text") or ""
        body_bits = [
            f"detection_rule_id={row.get('detection_rule_id')}",
            f"attack_pattern_id={row.get('attack_pattern_id')}",
            f"rule_name={row.get('rule_name')}",
            f"protocol={row.get('protocol')}",
            f"category={row.get('category')}",
            f"action={row.get('action')}",
            f"detection_scope={row.get('detection_scope')}",
        ]
        if row.get("required_fields"):
            body_bits.append(f"required_fields={row.get('required_fields')}")
        if row.get("rule_logic"):
            body_bits.append(f"rule_logic={row.get('rule_logic')}")
        out.append(
            {
                "rule": text[:500],
                "sid": compiled.get("sid") or "",
                "source": f"detection_rule:{row.get('detection_rule_id')}",
                "grounded": True,
                "from": "detection_rule",
                "attack_pattern_id": row.get("attack_pattern_id"),
                "detection_rule_id": row.get("detection_rule_id"),
                "status": row.get("status"),
                "confidence": float(row["confidence"]) if row.get("confidence") is not None else None,
                "valid": compiled.get("valid", False),
                "summary": "; ".join(str(b) for b in body_bits),
            }
        )
    return out


def _from_detection_table(query: str, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        from app.database import postgres
        from app.ontology.suricata_compiler import compile_rule
    except Exception:
        return []
    if not postgres.is_available():
        return []

    pattern_ids: list[str] = []
    rule_ids: list[str] = []
    blob = " ".join(
        [query or ""]
        + [str(e.get("body") or "") for e in evidence[:8]]
        + [str(e.get("source") or "") for e in evidence[:8]]
    )
    for m in _PATTERN_RE.finditer(blob):
        token = m.group(1).upper()
        if token.startswith("AP"):
            pattern_ids.append(token)
        else:
            rule_ids.append(token)

    low = (query or "").lower()
    sql = """
        SELECT detection_rule_id, attack_pattern_id, rule_name, protocol, category,
               action, confidence, status, suricata_text, severity,
               required_fields, rule_logic, detection_scope
        FROM detection_rule
        WHERE status IN ('PRODUCTION', 'TESTING')
    """
    params: list[Any] = []
    # Exact Suricata rule-name / sid from the question (highest precision).
    rule_name_m = re.search(r"\b(TEL-[A-Z0-9][A-Z0-9._-]{6,})\b", query or "", re.I)
    sid_m = re.search(r"\bsid\s*[:=]?\s*(\d{5,})\b", query or "", re.I) or re.search(
        r"\b(9000\d{2}|9001\d{2})\b", query or ""
    )
    if rule_name_m or sid_m:
        clauses = []
        if rule_name_m:
            clauses.append("lower(rule_name) = lower(%s)")
            params.append(rule_name_m.group(1))
            clauses.append("lower(rule_name) LIKE lower(%s)")
            params.append(f"%{rule_name_m.group(1)}%")
        if sid_m:
            clauses.append("COALESCE(suricata_text,'') LIKE %s")
            params.append(f"%sid:{sid_m.group(1)}%")
        sql += " AND (" + " OR ".join(clauses) + ")"
    elif pattern_ids or rule_ids:
        clauses = []
        if pattern_ids:
            clauses.append("attack_pattern_id = ANY(%s)")
            params.append(pattern_ids)
        if rule_ids:
            clauses.append("detection_rule_id = ANY(%s)")
            params.append(rule_ids)
        sql += " AND (" + " OR ".join(clauses) + ")"
    elif any(
        k in low
        for k in (
            "suricata", "detection", "rule", "attack", "hijack", "ulr",
            "create session", "ati", "sai", "unauthorized", "apn", "routing",
            "probing", "vector", "roaming", "gtp",
        )
    ):
        likes: list[str] = []
        for token in (
            "ulr", "diameter", "gtp", "ss7", "ati", "sai", "csr", "create session",
            "air", "unauthorized", "apn", "routing", "hijack", "probing", "roaming",
            "vector", "session", "context",
        ):
            if token in low:
                likes.append(token)
        if likes:
            parts = []
            for tok in likes:
                parts.append(
                    "(lower(rule_name) LIKE %s OR lower(protocol) LIKE %s OR "
                    "lower(COALESCE(rule_logic,'')) LIKE %s OR lower(category) LIKE %s OR "
                    "lower(COALESCE(attack_pattern_id,'')) LIKE %s)"
                )
                params.extend([f"%{tok}%", f"%{tok}%", f"%{tok}%", f"%{tok}%", f"%{tok}%"])
            sql += " AND (" + " OR ".join(parts) + ")"
    else:
        return []
    if "ulr" in low or "update location" in low:
        sql += (
            " ORDER BY CASE WHEN position('ulr' in lower(rule_name)) > 0 "
            "OR position('update' in lower(rule_name)) > 0 "
            "OR position('location' in lower(rule_name)) > 0 THEN 0 ELSE 1 END, "
            "confidence DESC NULLS LAST LIMIT 5"
        )
    else:
        sql += " ORDER BY confidence DESC NULLS LAST LIMIT 5"

    try:
        rows = postgres.fetch_all(sql, tuple(params))
    except Exception:
        return []

    return _rows_to_rules(rows, compile_rule)
