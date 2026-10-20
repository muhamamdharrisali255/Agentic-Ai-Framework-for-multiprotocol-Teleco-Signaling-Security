"""Operator IDS for Case 1 — detect GSMA category and block using rules.

IPS agent captures traffic; this module runs CAT1 → CAT2 → CAT3 and returns
the category + enforcement decision. The rule generator fills in PROPOSED
rules when no enrolled signature matches.
"""

from __future__ import annotations

import re
from typing import Any

from app.agent.parser import AgentContext


_OPCODE_RE = re.compile(r"\bopcode\s*[:=]\s*(\d+)", re.I)
_CMD_RE = re.compile(r"\b(?:command[_-]?code|cmd)\s*[:=]\s*(\d+)", re.I)
_GT_RE = re.compile(r"\b(?:calling[_-]?gt|global[_-]?title|gt)\s*[:=]\s*([0-9]+)", re.I)
_REALM_RE = re.compile(r"\b(?:origin[_-]?realm)\s*[:=]\s*([^\s,;]+)", re.I)
_HOST_RE = re.compile(r"\b(?:origin[_-]?host)\s*[:=]\s*([^\s,;]+)", re.I)


def run_operator_ids(agent_ctx: AgentContext, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Detect CAT1/CAT2/CAT3 and decide ALLOW / BLOCK / ESCALATE using rules."""
    message = observation_to_ids_message(agent_ctx, extra)
    try:
        from app.ids.category_router import get_router

        result = get_router().inspect(message)
        final = result.final_decision
        decision = (
            final.decision.value
            if hasattr(final.decision, "value")
            else str(final.decision)
        )
        category = (
            final.category.value
            if hasattr(final.category, "value")
            else str(final.category or "")
        )
        rule = final.rule_match
        rule_payload = {}
        if rule is not None:
            rule_payload = {
                "rule_id": rule.rule_id,
                "sid": rule.sid,
                "name": rule.name,
                "category": rule.category or category,
                "severity": rule.severity,
                "reference": rule.reference,
                "matched_fields": rule.matched_fields,
            }
        blocked = decision == "BLOCK"
        action = "BLOCK" if blocked else ("ESCALATE" if decision == "ESCALATE" else "ALLOW")
        return {
            "decision": decision,
            "category": category,
            "action": action,
            "blocked": blocked,
            "reason": final.reason,
            "explanation": final.explanation,
            "rule": rule_payload,
            "rule_id": rule_payload.get("rule_id") or final.detection_rule or "",
            "protocol": str(final.protocol.value if hasattr(final.protocol, "value") else final.protocol),
            "procedure": final.procedure,
            "enforcement": final.enforcement,
            "dry_run": final.dry_run,
            "event_id": result.event_id,
            "cat1": _decision_brief(result.cat1_result),
            "cat2": _decision_brief(result.cat2_result),
            "cat3": _decision_brief(result.cat3_result),
            "message": message,
        }
    except Exception as exc:
        return {
            "decision": "ALLOW",
            "category": "",
            "action": "ALLOW",
            "blocked": False,
            "reason": f"operator_ids_unavailable: {exc}",
            "rule": {},
            "message": message,
        }


def observation_to_ids_message(
    agent_ctx: AgentContext,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Map IPS Agent Context + extra observation fields to CAT inspect payload."""
    extra = dict(extra or {})
    blob = " ".join(
        [agent_ctx.event_type, agent_ctx.protocol]
        + list(agent_ctx.observations)
        + list(agent_ctx.entities)
        + list(agent_ctx.ids_alerts)
    )
    traffic = agent_ctx.ips_traffic if isinstance(agent_ctx.ips_traffic, dict) else {}

    protocol = str(
        extra.get("protocol") or traffic.get("protocol") or agent_ctx.protocol or ""
    )
    procedure = str(
        extra.get("procedure")
        or extra.get("command")
        or traffic.get("procedure")
        or agent_ctx.event_type
        or ""
    )
    opcode = extra.get("opcode") or extra.get("command_code")
    if opcode is None:
        m = _OPCODE_RE.search(blob) or _CMD_RE.search(blob)
        opcode = int(m.group(1)) if m else None
    calling_gt = str(
        extra.get("calling_gt") or extra.get("global_title") or traffic.get("calling_gt") or ""
    )
    if not calling_gt:
        m = _GT_RE.search(blob)
        calling_gt = m.group(1) if m else ""
    origin_realm = str(extra.get("origin_realm") or traffic.get("origin_realm") or "")
    if not origin_realm:
        m = _REALM_RE.search(blob)
        origin_realm = m.group(1) if m else ""
    origin_host = str(extra.get("origin_host") or traffic.get("origin_host") or "")
    if not origin_host:
        m = _HOST_RE.search(blob)
        origin_host = m.group(1) if m else ""

    return {
        "protocol": protocol,
        "procedure": procedure,
        "opcode": opcode,
        "direction": str(extra.get("direction") or "INBOUND").upper(),
        "source": str(extra.get("source") or agent_ctx.source_ip or ""),
        "destination": str(extra.get("destination") or agent_ctx.destination_ip or ""),
        "calling_gt": calling_gt,
        "global_title": calling_gt,
        "origin_realm": origin_realm,
        "origin_host": origin_host,
        "imsi": str(extra.get("imsi") or agent_ctx.subscriber or ""),
        "subscriber_id": agent_ctx.subscriber,
        "serving_network": str(extra.get("serving_network") or extra.get("mcc_mnc") or ""),
        "apn": str(extra.get("apn") or ""),
        "source_gateway": str(extra.get("source_gateway") or agent_ctx.source_ip or ""),
        "latitude": extra.get("latitude"),
        "longitude": extra.get("longitude"),
        "event_type": agent_ctx.event_type or extra.get("event_type") or "",
        "map_version": str(extra.get("map_version") or ""),
        "cap_version": str(extra.get("cap_version") or ""),
        "gtp_version": str(extra.get("gtp_version") or ""),
    }


def _decision_brief(decision: Any) -> dict[str, Any] | None:
    if decision is None:
        return None
    d = decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision)
    cat = decision.category.value if hasattr(decision.category, "value") else str(decision.category)
    return {
        "decision": d,
        "category": cat,
        "reason": getattr(decision, "reason", "") or "",
        "rule_id": getattr(decision, "detection_rule", "") or "",
    }
