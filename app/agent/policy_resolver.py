"""Policy resolver — Case 3 Step 0 (imoplementation_plan_updated.md §5).

Parses analyst policy instructions onto taxonomy facets and returns every
matching attack_pattern row (and linked detection_rule when present).
"""

from __future__ import annotations

import re
from typing import Any

from app.agent.taxonomy_classifier import TaxonomyFacets, classify_taxonomy_facets, is_policy_instruction
from app.database import postgres


def resolve_policy(query: str) -> dict[str, Any]:
    """Resolve a policy instruction to taxonomy facets + attack_pattern rows."""
    facets = classify_taxonomy_facets(query)
    patterns = _match_attack_patterns(facets, query)
    rules = _detection_rules_for_patterns([p.get("attack_pattern_id") for p in patterns])

    return {
        "policy_instruction": (query or "").strip(),
        "taxonomy": facets.as_dict(),
        "attack_patterns": patterns,
        "detection_rules": rules,
        "pattern_count": len(patterns),
        "rule_count": len(rules),
    }


def _match_attack_patterns(facets: TaxonomyFacets, query: str) -> list[dict[str, Any]]:
    if not postgres.is_available():
        return _fallback_patterns(facets)

    clauses: list[str] = []
    params: list[Any] = []

    for cat in facets.categories or ([facets.category] if facets.category else []):
        c = cat.upper().replace("CATEGORY", "CAT").replace(" ", "")
        clauses.append(
            "(upper(category) = %s OR upper(category) LIKE %s OR upper(category) LIKE %s)"
        )
        params.extend([c, f"%{c}%", f"%{c.replace('.', '/')}%"])

    for proto in facets.protocols or ([facets.protocol] if facets.protocol else []):
        clauses.append("lower(protocol_scope) LIKE %s")
        params.append(f"%{proto.lower()}%")

    if facets.attack_type:
        clauses.append("lower(attack_objective) LIKE %s")
        params.append(f"%{facets.attack_type.lower()}%")

    if not clauses and is_policy_instruction(query):
        # Generic block-all without explicit facet — return CAT2 family per plan example.
        if re.search(r"\bcat\s*2\b|\bcat2\b", query, re.I):
            clauses.append("(upper(category) LIKE %s OR upper(category) LIKE %s)")
            params.extend(["%CAT2%", "%CAT2/%"])

    if not clauses:
        return []

    sql = f"""
        SELECT attack_pattern_id, attack_name, protocol_scope, category,
               initiating_message, attack_objective, severity
        FROM attack_pattern
        WHERE {' OR '.join(clauses)}
        ORDER BY attack_pattern_id
    """
    return list(postgres.fetch_all(sql, tuple(params)))


def _detection_rules_for_patterns(pattern_ids: list[str | None]) -> list[dict[str, Any]]:
    ids = [p for p in pattern_ids if p]
    if not ids or not postgres.is_available():
        return []
    return list(
        postgres.fetch_all(
            """
            SELECT detection_rule_id, attack_pattern_id, rule_name, protocol, category,
                   detection_scope, required_fields, rule_logic, action, severity, status
            FROM detection_rule
            WHERE attack_pattern_id = ANY(%s)
            ORDER BY detection_rule_id
            """,
            (ids,),
        )
    )


def _fallback_patterns(facets: TaxonomyFacets) -> list[dict[str, Any]]:
    """In-memory fallback when Postgres is unavailable (tests/dev)."""
    seed = [
        ("AP006", "Authentication-to-Session Anomaly", "Diameter+GTP-C", "CAT2/CAT3.2"),
        ("AP007", "Cross-Protocol Subscriber Probing", "SS7+Diameter", "CAT2/CAT3.2"),
        ("AP008", "Cross-Protocol Roaming Session Abuse", "SS7 + Diameter + GTP-C", "CAT2/CAT3.2"),
        ("AP009", "GTP Session Without Signaling Context", "GTP-C", "CAT2/CAT3.2"),
        ("AP010", "Unauthorized APN/Routing Behavior", "GTP-C", "CAT2/CAT3.2"),
    ]
    out: list[dict[str, Any]] = []
    target_cats = {c.upper() for c in (facets.categories or ([facets.category] if facets.category else []))}
    for row in seed:
        ap_id, name, proto, cat = row
        if not target_cats:
            continue
        cat_up = cat.upper()
        if any(tc in cat_up or cat_up.startswith(tc) for tc in target_cats):
            out.append(
                {
                    "attack_pattern_id": ap_id,
                    "attack_name": name,
                    "protocol_scope": proto,
                    "category": cat,
                    "attack_objective": "",
                    "severity": "HIGH",
                }
            )
    return out
