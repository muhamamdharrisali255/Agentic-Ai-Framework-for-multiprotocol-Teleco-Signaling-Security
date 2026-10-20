"""Query classification (implementation_plan.md §18)."""

from __future__ import annotations

import re
from typing import Any

from app.retrieval.document_registry import extract_identifiers


def classify_query(
    query: str,
    entities: dict[str, Any] | None = None,
    *,
    agent_context: Any = None,
) -> str:
    q = (query or "").lower()
    entities = entities or {}
    conceptual = any(q.startswith(p) for p in ("what is", "what are", "explain", "describe", "define"))
    has_subscriber = bool(entities.get("subscriber_id") or entities.get("imsi") or re.search(r"\bsub\d{3,}\b", q, re.I))
    observed = bool(getattr(agent_context, "has_observation", False))

    if observed and any(
        x in q
        for x in (
            "malicious", "suspicious", "anomal", "investigate", "attack",
            "hijack", "ids", "ips", "alert", "flagged", "is this",
        )
    ):
        return "SECURITY_INVESTIGATION"
    if observed and not conceptual:
        return "SECURITY_INVESTIGATION"

    if has_subscriber and any(x in q for x in ("alert", "attack", "flagged", "suspicious", "ids", "why was")):
        return "SECURITY_INVESTIGATION"
    if any(x in q for x in ("subscriber", "sub00", "imsi", "msisdn")):
        if any(x in q for x in ("alert", "attack", "flagged", "suspicious", "ids", "why was")):
            return "SECURITY_INVESTIGATION"
        return "SUBSCRIBER_ANALYSIS"
    if any(x in q for x in ("session", "gtp session", "teid")):
        if has_subscriber and any(x in q for x in ("attack", "suspicious", "hijack", "match", "flagged")):
            return "SECURITY_INVESTIGATION"
        if not conceptual and any(x in q for x in ("attack", "suspicious", "hijack", "match")):
            return "SECURITY_INVESTIGATION"
        if not conceptual:
            return "SESSION_ANALYSIS"
    _threat_words = (
        "attack", "threat", "indicator", "hijack", "abuse", "ids",
        "interception", "intercept", "fraud", "malicious", "anomal",
    )
    if any(x in q for x in _threat_words):
        return "THREAT_ANALYSIS"
    # Inventory / describe-protocol questions are standards knowledge — not threat analysis.
    # (Previously "list down … diameter" was forced to THREAT_ANALYSIS and broke CAT-2 lists.)
    if any(x in q for x in ("describe", "detail", "list down", "list ", "which ", "what ")) and any(
        x in q for x in ("ss7", "sms", "gtp", "diameter", "map", "s6a")
    ):
        return "DOCUMENT_KNOWLEDGE"
    if "sms" in q and any(x in q for x in ("ss7", "fraud", "intercept", "smishing", "spam", "spoof")):
        return "THREAT_ANALYSIS"
    if any(
        x in q
        for x in (
            "tadig", "operator", "mcc", "mnc", "which operator",
            "ir.21", "ir21", "raex",
            "sccp carrier", "sccp gateway", "international sccp",
            "camel info", "camel", "gsmssf", "cap version", "capv",
            "global title", " gt ", "gts of", "list all gt",
        )
    ):
        return "STRUCTURED_LOOKUP"
    if entities.get("subscriber_id") or entities.get("imsi"):
        return "SUBSCRIBER_ANALYSIS"
    if entities.get("session_id"):
        return "SESSION_ANALYSIS"
    if any(x in q for x in (" and ", " why ", " does ", " match ")):
        return "MIXED"
    return "DOCUMENT_KNOWLEDGE"


def extract_entities(query: str) -> dict[str, Any]:
    q = query or ""
    out: dict[str, Any] = {}
    m = re.search(r"\bSUB\d{3,}\b", q, re.I)
    if m:
        out["subscriber_id"] = m.group(0).upper()
    m = re.search(r"\bIMSI\s*[:=]?\s*(\d{10,15})\b", q, re.I)
    if m:
        out["imsi"] = m.group(1)
    m = re.search(r"\bMSISDN\s*[:=]?\s*(\+?\d{8,15})\b", q, re.I)
    if m:
        out["msisdn"] = m.group(1)
    m = re.search(r"\b(?:session|sess)(?:\s*id)?\s*[:=]\s*([A-Za-z0-9_-]{4,})\b", q, re.I)
    if m and m.group(1).lower() not in ("hijack", "hijacking", "management"):
        out["session_id"] = m.group(1)
    m = re.search(r"\b(GTP-?\d{3,}|SS7-?\d{3,}|RULE-[A-Z0-9-]+)\b", q, re.I)
    if m:
        out["attack_id"] = m.group(1).upper()
    for proto in ("GTP", "Diameter", "SS7", "S6a", "MAP"):
        if proto.lower() in q.lower():
            out["protocol"] = proto
            break
    m = re.search(r"\bTADIG\s+([A-Z]{5})\b", q, re.I)
    if m:
        out["tadig"] = m.group(1).upper()
    out.update(extract_identifiers(q, out))
    return out
