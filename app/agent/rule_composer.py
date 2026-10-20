"""Compose PROPOSED detection rules from live IPS context + message_policy.

Used when no enrolled detection_rule (DR00x) matches the observation.
Does not write to the database — returns analyst-reviewable rule specs only.
"""

from __future__ import annotations

import re
from typing import Any

from app.agent.parser import AgentContext
from app.ontology.policy_knowledge import search_policy
from app.ontology.suricata_compiler import compile_rule


def compose_rules_from_ips(
    agent_ctx: AgentContext,
    *,
    query: str = "",
) -> list[dict[str, Any]]:
    """Build one or more PROPOSED rules grounded in message_policy + IPS observation."""
    if not agent_ctx.has_observation:
        return []

    search_q = _ips_search_query(agent_ctx, query)
    policies = list((search_policy(search_q).get("evidence") or []))
    if not policies and agent_ctx.protocol:
        policies = list(
            (search_policy(f"{agent_ctx.protocol} inbound {agent_ctx.event_type or ''}").get("evidence") or [])
        )

    if not policies:
        return []

    out: list[dict[str, Any]] = []
    for item in policies[:2]:
        parsed = _parse_policy_body(str(item.get("body") or ""))
        if not parsed.get("policy_id"):
            continue
        rule = _build_proposed_rule(agent_ctx, parsed)
        if rule:
            out.append(rule)
    return out


def _ips_search_query(agent_ctx: AgentContext, query: str) -> str:
    parts = [
        query or "",
        agent_ctx.protocol or "",
        agent_ctx.event_type or "",
        agent_ctx.subscriber or "",
        agent_ctx.source_ip or "",
    ]
    parts.extend(agent_ctx.entities)
    parts.extend(agent_ctx.observations)
    for alert in agent_ctx.ids_alerts:
        if alert and not str(alert).lower().startswith("sid:"):
            parts.append(str(alert))
    return " ".join(p for p in parts if p).strip()


def _parse_policy_body(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in body.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        out[key.strip().lower()] = val.strip()
    return out


def _build_proposed_rule(agent_ctx: AgentContext, policy: dict[str, str]) -> dict[str, Any] | None:
    policy_id = policy.get("policy_id") or ""
    protocol = policy.get("protocol") or agent_ctx.protocol or "signalling"
    message = policy.get("message") or agent_ctx.event_type or "UNKNOWN"
    category = policy.get("category") or "CAT3.2"
    action = (policy.get("action") or "ALERT").upper()
    checks = policy.get("validation_fields") or ""

    rule_name = _suggest_rule_name(protocol, message, category)
    proposed_id = f"PROPOSED-{policy_id}"

    compiled = compile_rule(
        {
            "detection_rule_id": proposed_id,
            "rule_name": rule_name,
            "action": action,
            "suricata_text": "",
        }
    )

    obs_bits = [o for o in agent_ctx.observations if o][:4]
    if agent_ctx.source_ip:
        obs_bits.append(f"source_ip={agent_ctx.source_ip}")
    if agent_ctx.subscriber:
        obs_bits.append(f"subscriber={agent_ctx.subscriber}")
    rule_logic = (
        f"Live IPS/{protocol} observation"
        + (f" ({agent_ctx.event_type})" if agent_ctx.event_type else "")
        + ": "
        + "; ".join(obs_bits)
    )

    summary = (
        f"status=PROPOSED; policy_id={policy_id}; category={category}; "
        f"protocol={protocol}; message={message}; action={action}; "
        f"required_fields={checks}; rule_logic={rule_logic}; "
        f"grounding=message_policy+ips_context"
    )

    return {
        "rule": compiled.get("suricata_text") or "",
        "sid": str(compiled.get("sid") or ""),
        "source": f"proposed:{policy_id}",
        "grounded": False,
        "proposed": True,
        "from": "ips_compose",
        "detection_rule_id": proposed_id,
        "policy_id": policy_id,
        "status": "PROPOSED",
        "action": action,
        "category": category,
        "protocol": protocol,
        "message": message,
        "checks": checks,
        "valid": compiled.get("valid", False),
        "placeholder": compiled.get("placeholder", True),
        "summary": summary,
        "note": (
            f"Proposed detection rule composed from {policy_id} and live IPS observation "
            "(not enrolled — analyst review required before PRODUCTION)."
        ),
    }


def _suggest_rule_name(protocol: str, message: str, category: str) -> str:
    proto = re.sub(r"[^A-Z0-9]", "", (protocol or "SIG").upper())[:8] or "SIG"
    msg = re.sub(r"[^A-Za-z0-9]", "", message or "EVENT")[:20].upper()
    cat = re.sub(r"[^A-Z0-9.]", "", (category or "CAT3").upper())
    return f"TEL-{proto}-{cat}-{msg}-PROPOSED"


def should_use_rule_draft(rules: list[dict[str, Any]], agent_ctx: AgentContext) -> bool:
    """True when live IPS observation yielded a PROPOSED (composed) rule."""
    if not agent_ctx.has_observation:
        return False
    return any(r.get("proposed") for r in rules)


def summarize_defined_rule(rule: dict[str, Any]) -> str:
    """One-paragraph operator summary of a rule the Case-3 agent defined."""
    name = rule.get("rule_name") or rule.get("name") or rule.get("msg") or "detection rule"
    proto = rule.get("protocol") or "signaling"
    cat = rule.get("category") or ""
    action = (rule.get("action") or "").upper() or "ALERT"
    ap = rule.get("attack_pattern_id") or ""
    rid = rule.get("detection_rule_id") or rule.get("rule_id") or ""
    sid = rule.get("sid") or ""
    checks = rule.get("checks") or rule.get("required_fields") or ""
    bits = [
        f"{name} is a {cat or 'GSMA'} {proto} rule".strip(),
        f"action {action}" + (" (Suricata drop)" if action == "BLOCK" else ""),
    ]
    if rid:
        bits.append(f"id {rid}")
    if sid:
        bits.append(f"sid {sid}")
    if ap:
        bits.append(f"covers {ap}")
    if checks:
        bits.append(f"checks {checks}")
    existing = str(rule.get("summary") or "").strip()
    if existing and "status=" not in existing[:20]:
        return existing
    return "; ".join(bits) + "."


def ensure_summary_section(answer: str, rules: list[dict[str, Any]] | None = None) -> str:
    """Guarantee a ## Summary section on Case-3 rule-agent output."""
    text = (answer or "").strip()
    if re.search(r"(?im)^##\s*summary\b", text):
        return text
    lines = ["## Summary"]
    if rules:
        for r in rules[:4]:
            if not isinstance(r, dict):
                continue
            lines.append(f"- {summarize_defined_rule(r)}")
    else:
        lines.append(
            "- The rule agent drafted a detection rule from the policy/attack scope above; "
            "review action (alert vs drop) before PRODUCTION."
        )
    return text + ("\n\n" if text else "") + "\n".join(lines)
