"""IPS + IDS incident parser — capture traffic, resolve/compose rules, feed main agent.

Pipeline (Case 1):
  1. IPS agent normalizes live traffic (Suricata EVE or signalling JSON)
  2. IDS Phase-1 rule match + Phase-2 IR.21 cross-check
  3. Enriched observation (traffic + rule + BLOCK/ALERT) → main agent reasoning
"""

from __future__ import annotations

import re
from typing import Any

from app.agent.ids_engine import run_ids_pipeline
from app.agent.ips_agent import capture, is_raw_ips_payload
from app.agent.parser import AgentContext, parse_agent_context


def parse_ips_ids_incident(
    raw: dict[str, Any] | None,
    *,
    protocol: str = "",
    query: str = "",
) -> dict[str, Any]:
    """Capture IPS traffic, run IDS Phase-1/2, return bundle for main agent."""
    payload = dict(raw or {})
    cap: dict[str, Any] = {}

    if is_raw_ips_payload(payload):
        cap = capture(payload, protocol=protocol or str(payload.get("protocol") or ""))
        base_ctx = dict(cap.get("agent_context") or {})
    else:
        base_ctx = payload

    agent_ctx = parse_agent_context(query, base_ctx)
    extra = dict(payload)
    extra.update(base_ctx if isinstance(base_ctx, dict) else {})
    ids_result = run_ids_pipeline(
        agent_ctx,
        query=query or "What attack is this and which detection rule applies?",
        extra=extra,
    )
    rules = list(ids_result.get("detection_rules") or [])
    top = (ids_result.get("phase1") or {}).get("top_rule") or (rules[0] if rules else {})
    action = ids_result.get("ids_action") or _rule_action(top)
    blocked = bool(ids_result.get("blocked"))
    ids_rule = _rule_payload(top)
    ips_traffic = _traffic_payload(agent_ctx, cap)

    enriched = {
        **agent_ctx.as_dict(),
        "ips_traffic": ips_traffic,
        "ids_rule": ids_rule,
        "ids_action": action,
        "blocked": blocked,
        "rule_status": ids_rule.get("status") or "",
        "detection_rules": rules[:3],
        "ids_verification": {
            "phase1": ids_result.get("phase1"),
            "phase2": ids_result.get("phase2"),
            "operator_ids": ids_result.get("operator_ids"),
            "confirmed_anomaly": ids_result.get("confirmed_anomaly"),
        },
    }
    if cap.get("event"):
        enriched["ips_event_id"] = str((cap.get("event") or {}).get("event_id") or "")

    return {
        "capture": cap,
        "agent_context": enriched,
        "detection_rules": rules[:5],
        "ids_rule": ids_rule,
        "ips_traffic": ips_traffic,
        "blocked": blocked,
        "ids_action": action,
        "proposed": bool(ids_rule.get("proposed") or ids_result.get("proposed")),
        "category": ids_result.get("category") or ids_rule.get("category") or "",
        "rule_generator": bool(ids_result.get("rule_generator") or ids_result.get("proposed")),
        "ids_verification": enriched["ids_verification"],
    }


def observation_for_agent(bundle: dict[str, Any]) -> dict[str, Any]:
    """Observation dict passed to run_agent_graph / parse_agent_context."""
    return dict(bundle.get("agent_context") or {})


def _traffic_payload(agent_ctx: AgentContext, cap: dict[str, Any]) -> dict[str, Any]:
    event = cap.get("event") or {}
    return {
        "protocol": agent_ctx.protocol,
        "event_type": agent_ctx.event_type,
        "source_ip": agent_ctx.source_ip,
        "destination_ip": agent_ctx.destination_ip,
        "subscriber": agent_ctx.subscriber,
        "session": agent_ctx.session,
        "severity": agent_ctx.severity or event.get("severity"),
        "observations": list(agent_ctx.observations),
        "entities": list(agent_ctx.entities),
        "ids_alerts": list(agent_ctx.ids_alerts),
        "event_id": event.get("event_id"),
        "raw_reference": event.get("raw_reference"),
    }


def _rule_payload(rule: dict[str, Any]) -> dict[str, Any]:
    if not rule:
        return {}
    status = str(rule.get("status") or "")
    if not status:
        if rule.get("proposed"):
            status = "PROPOSED"
        elif rule.get("from") == "detection_rule" and rule.get("grounded"):
            status = "ENROLLED"
    return {
        "detection_rule_id": rule.get("detection_rule_id") or "",
        "policy_id": rule.get("policy_id") or "",
        "rule_name": _rule_name(rule),
        "action": _rule_action(rule),
        "sid": str(rule.get("sid") or ""),
        "category": rule.get("category") or "",
        "protocol": rule.get("protocol") or "",
        "checks": rule.get("checks") or "",
        "summary": rule.get("summary") or "",
        "suricata_text": rule.get("rule") or "",
        "proposed": bool(rule.get("proposed")),
        "grounded": bool(rule.get("grounded")),
        "status": status,
        "note": rule.get("note") or "",
    }


def _rule_action(rule: dict[str, Any]) -> str:
    action = str(rule.get("action") or "").upper()
    if action:
        return action
    summary = str(rule.get("summary") or "").lower()
    if "action=block" in summary:
        return "BLOCK"
    if "action=alert" in summary:
        return "ALERT"
    return ""


def _rule_name(rule: dict[str, Any]) -> str:
    summary = str(rule.get("summary") or "")
    m = re.search(r"rule_name=([^;]+)", summary)
    if m:
        return m.group(1).strip()
    if rule.get("proposed"):
        return str(rule.get("detection_rule_id") or "PROPOSED-RULE")
    return ""
