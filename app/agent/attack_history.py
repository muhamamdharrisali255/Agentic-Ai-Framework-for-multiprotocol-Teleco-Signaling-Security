"""Case 3 — classify a new attack from conversation history + enrolled patterns.

When an analyst reports a novel observation, match it against attack_pattern
history (AP001–AP010) and prior chat turns, then explain the category.
"""

from __future__ import annotations

import re
from typing import Any

from app.agent.taxonomy_classifier import TaxonomyFacets, classify_taxonomy_facets


_NEW_ATTACK = re.compile(
    r"\b(new\s+attack|unknown\s+attack|novel\s+attack|first\s+time|"
    r"never\s+seen|classify\s+(this\s+)?attack|explain\s+(this\s+)?attack|"
    r"what\s+attack\s+is\s+this|emerging\s+threat|new\s+threat)\b",
    re.I,
)
_AP_RE = re.compile(r"\b(AP\d{3}|DR\d{3}|CAT\s*[123](?:\.\d)?)\b", re.I)


def is_new_attack_query(query: str) -> bool:
    return bool(_NEW_ATTACK.search(query or ""))


def classify_attack_from_history(
    query: str,
    *,
    history: list[dict[str, str]] | None = None,
    observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify a (possibly new) attack using taxonomy + enrolled patterns + chat history."""
    facets = classify_taxonomy_facets(query)
    history_hits = _history_mentions(history)
    patterns = _match_patterns(facets, query)
    related = _related_from_history(history_hits, patterns)

    category = facets.category or (patterns[0].get("category") if patterns else "")
    protocol = facets.protocol or (patterns[0].get("protocol_scope") if patterns else "")
    if observation:
        protocol = protocol or str(observation.get("protocol") or "")

    known = bool(patterns) or bool(related)
    explanation = _explain(query, facets, patterns, related, known)

    return {
        "is_new_attack": is_new_attack_query(query) and not known,
        "known_from_history": known,
        "category": category,
        "protocol": protocol,
        "taxonomy": facets.as_dict(),
        "matched_patterns": patterns[:5],
        "history_related": related[:5],
        "explanation": explanation,
        "summary": explanation.split("\n", 1)[0][:400],
    }


def _history_mentions(history: list[dict[str, str]] | None) -> list[str]:
    hits: list[str] = []
    for turn in history or []:
        text = str(turn.get("content") or turn.get("text") or "")
        hits.extend(m.group(1).upper().replace(" ", "") for m in _AP_RE.finditer(text))
    return list(dict.fromkeys(hits))


def _match_patterns(facets: TaxonomyFacets, query: str) -> list[dict[str, Any]]:
    try:
        from app.agent.policy_resolver import _match_attack_patterns

        rows = _match_attack_patterns(facets, query)
        if rows:
            return rows
    except Exception:
        pass
    return []


def _related_from_history(
    mentions: list[str],
    patterns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    related: list[dict[str, Any]] = []
    seen = {str(p.get("attack_pattern_id") or "") for p in patterns}
    for token in mentions:
        if token in seen:
            continue
        if token.startswith("AP") or token.startswith("DR") or token.startswith("CAT"):
            related.append({"ref": token, "from": "chat_history"})
            seen.add(token)
    return related


def _explain(
    query: str,
    facets: TaxonomyFacets,
    patterns: list[dict[str, Any]],
    related: list[dict[str, Any]],
    known: bool,
) -> str:
    proto = facets.protocol or "signaling"
    cat = facets.category or "unclassified"
    if patterns:
        top = patterns[0]
        name = top.get("attack_name") or top.get("attack_pattern_id") or "enrolled pattern"
        ap = top.get("attack_pattern_id") or ""
        obj = top.get("attack_objective") or ""
        hist = ""
        if related:
            hist = " Prior chat already referenced " + ", ".join(r["ref"] for r in related[:4]) + "."
        return (
            f"Classified as {top.get('category') or cat} on {top.get('protocol_scope') or proto} "
            f"matching enrolled pattern {ap} ({name}). {obj}{hist}"
        ).strip()
    if related:
        refs = ", ".join(r["ref"] for r in related[:4])
        return (
            f"No exact enrolled pattern for this {proto} event; conversation history "
            f"points to {refs}. Treat as related to those categories until a new AP/DR is drafted."
        )
    if known:
        return f"Mapped to {cat} / {proto} from the current question taxonomy."
    return (
        f"No enrolled attack_pattern matched this {proto} observation "
        f"(taxonomy guess: {cat}). Treat as a candidate new attack; draft a detection rule "
        f"and confirm against FS.11/FS.19/FS.20 before PRODUCTION."
    )
