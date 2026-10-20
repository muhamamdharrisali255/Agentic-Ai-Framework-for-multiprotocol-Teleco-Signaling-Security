"""Two-phase IDS engine — Case 1 from imoplementation_plan_updated.md.

Phase 1: deterministic detection_rule match (no LLM).
Phase 2: IR.21 Postgres cross-check (roaming agreement / realm validity).
"""

from __future__ import annotations

import re
from typing import Any

from app.agent.ids_agent import propose_rules
from app.agent.parser import AgentContext
from app.database import postgres


def run_phase1(
    agent_ctx: AgentContext,
    *,
    query: str = "",
) -> dict[str, Any]:
    """Match enrolled DR00x or compose PROPOSED rule from IPS observation."""
    rules = propose_rules(agent_ctx, [], query=query)
    top = rules[0] if rules else {}
    action = _rule_action(top)
    matched = bool(top.get("detection_rule_id") or top.get("proposed") or top.get("grounded"))
    anomaly = matched and bool(
        top.get("proposed") or top.get("grounded") or action in ("BLOCK", "ALERT")
    )
    if top:
        top = {**top, "action": action}
    return {
        "matched": matched,
        "anomaly": anomaly,
        "rules": rules[:5],
        "top_rule": top,
        "phase": 1,
    }


def run_phase2(
    agent_ctx: AgentContext,
    phase1: dict[str, Any],
) -> dict[str, Any]:
    """Corroborate Phase-1 flag against IR.21 plmn / diameter_realm tables."""
    if not phase1.get("anomaly"):
        return {
            "confirmed": False,
            "skipped": True,
            "reason": "phase1_no_anomaly",
            "phase": 2,
        }

    realm = _extract_realm(agent_ctx)
    host = _extract_host(agent_ctx)
    imsi = agent_ctx.subscriber or _extract_imsi(agent_ctx)

    checks: list[dict[str, Any]] = []
    confirmed = False

    if realm:
        realm_row = _lookup_diameter_realm(realm)
        checks.append({"check": "diameter_realm", "realm": realm, "row": realm_row})
        if realm_row is not None:
            authorized = bool(realm_row.get("authorized"))
            agreement = str(realm_row.get("agreement_status") or realm_row.get("status") or "").upper()
            if not authorized or agreement in ("INACTIVE", "SUSPENDED", "NONE"):
                confirmed = True

    if host and not confirmed:
        host_row = _lookup_diameter_host(host)
        checks.append({"check": "diameter_host", "host": host, "row": host_row})
        if host_row is not None and not bool(host_row.get("authorized")):
            confirmed = True

    if imsi and not confirmed:
        plmn_row = _lookup_plmn_from_imsi(imsi)
        checks.append({"check": "plmn_agreement", "imsi": imsi, "row": plmn_row})
        if plmn_row is not None:
            status = str(plmn_row.get("agreement_status") or "").upper()
            if status in ("NONE", "INACTIVE", "SUSPENDED", "UNKNOWN"):
                confirmed = True

    # When IR.21 has no rows, trust Phase-1 for live IPS (proposed or enrolled).
    if not checks and phase1.get("anomaly"):
        confirmed = True
        checks.append({"check": "phase1_only", "reason": "no_ir21_rows"})

    # Unknown realm with no IR.21 match → treat as roaming violation.
    if realm and not confirmed and not any(c.get("row") for c in checks):
        confirmed = True
        checks.append({"check": "unknown_realm", "realm": realm, "reason": "no_roaming_agreement"})

    return {
        "confirmed": confirmed,
        "skipped": False,
        "checks": checks,
        "realm": realm,
        "host": host,
        "imsi": imsi,
        "phase": 2,
    }


def run_ids_pipeline(
    agent_ctx: AgentContext,
    *,
    query: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Case 1: IPS context → operator CAT IDS (detect + block) → Phase-1/2 → rule generator."""
    from app.agent.operator_ids import run_operator_ids

    cat_ids = run_operator_ids(agent_ctx, extra)
    phase1 = run_phase1(agent_ctx, query=query)
    phase2 = run_phase2(agent_ctx, phase1)
    top = phase1.get("top_rule") or {}
    action = top.get("action") or _rule_action(top)
    live_enrolled = bool(top.get("grounded") and top.get("detection_rule_id") and agent_ctx.has_observation)
    confirmed = bool(phase2.get("confirmed") or (live_enrolled and phase1.get("anomaly")))
    cat_blocked = bool(cat_ids.get("blocked"))
    cat_action = str(cat_ids.get("action") or "")
    blocked = cat_blocked or (action == "BLOCK" and confirmed)
    if cat_blocked:
        ids_action = "BLOCK"
    elif cat_action == "ESCALATE":
        ids_action = "ESCALATE"
    else:
        ids_action = action if confirmed else (action or "ALERT")
    if cat_ids.get("rule") and not top.get("detection_rule_id") and not top.get("proposed"):
        cat_rule = cat_ids["rule"]
        top = {
            **top,
            "detection_rule_id": cat_rule.get("rule_id") or "",
            "rule_name": cat_rule.get("name") or "",
            "sid": cat_rule.get("sid") or "",
            "category": cat_ids.get("category") or cat_rule.get("category") or "",
            "action": ids_action,
            "from": "operator_ids",
            "summary": cat_ids.get("reason") or "",
        }
        rules = [top] + list(phase1.get("rules") or [])
    else:
        rules = list(phase1.get("rules") or [])
        if top:
            top = {**top, "category": top.get("category") or cat_ids.get("category") or ""}
    return {
        "phase1": phase1,
        "phase2": phase2,
        "operator_ids": cat_ids,
        "category": cat_ids.get("category") or top.get("category") or "",
        "detection_rules": rules[:5],
        "confirmed_anomaly": bool((phase1.get("anomaly") and confirmed) or cat_blocked),
        "blocked": blocked,
        "ids_action": ids_action,
        "proposed": bool(top.get("proposed")),
        "rule_generator": bool(top.get("proposed")),
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


def _extract_realm(ctx: AgentContext) -> str:
    blob = " ".join(ctx.observations + ctx.entities + ctx.ids_alerts)
    m = re.search(r"Origin-Realm[=:\s]+([^\s,;]+)", blob, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"origin[_-]?realm[\"']?\s*[:=]\s*[\"']?([^\s\"',;]+)", blob, re.I)
    return m.group(1).strip() if m else ""


def _extract_host(ctx: AgentContext) -> str:
    blob = " ".join(ctx.observations + ctx.entities)
    m = re.search(r"Origin-Host[=:\s]+([^\s,;]+)", blob, re.I)
    return m.group(1).strip() if m else ""


def _extract_imsi(ctx: AgentContext) -> str:
    blob = " ".join(ctx.observations + [ctx.subscriber or ""])
    m = re.search(r"\b(\d{14,15})\b", blob)
    return m.group(1) if m else ""


def _lookup_diameter_realm(realm: str) -> dict[str, Any] | None:
    if not postgres.is_available():
        return None
    row = postgres.fetch_one(
        """
        SELECT dr.realm, dr.authorized, dr.application, p.agreement_status, p.role
        FROM diameter_realm dr
        LEFT JOIN plmn p ON p.network_id = dr.network_id
        WHERE LOWER(dr.realm) = LOWER(%s)
        LIMIT 1
        """,
        (realm,),
    )
    return row


def _lookup_diameter_host(host: str) -> dict[str, Any] | None:
    if not postgres.is_available():
        return None
    return postgres.fetch_one(
        """
        SELECT host_name, realm, authorized, ip_address
        FROM diameter_host
        WHERE LOWER(host_name) = LOWER(%s)
        LIMIT 1
        """,
        (host,),
    )


def _lookup_plmn_from_imsi(imsi: str) -> dict[str, Any] | None:
    if not postgres.is_available() or len(imsi) < 5:
        return None
    mcc, mnc = imsi[:3], imsi[3:5]
    return postgres.fetch_one(
        """
        SELECT network_id, operator_name, mcc, mnc, plmn_id, agreement_status, role
        FROM plmn
        WHERE mcc = %s AND mnc = %s
        LIMIT 1
        """,
        (mcc, mnc),
    )
