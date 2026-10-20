"""Retrieval routing: choose semantic, structured, or both for a question.

The decision is evidence-driven rather than keyword-driven. The structured
store is probed first — it is an indexed SQL lookup, so the probe is cheap — and
the strength of that match, combined with whether the question asks for an
explanation, decides the route. A question that names a stored value routes to
SQL; a question asking what something means routes to the document corpus; a
question doing both gets both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

KNOWLEDGE = "KNOWLEDGE"
STRUCTURED = "STRUCTURED"
HYBRID = "HYBRID"

# Wording that asks for meaning, mechanism, or consequence — answerable only
# from the prose corpus, whatever the structured store happens to contain.
_EXPLANATORY = re.compile(
    r"\b(why|how|explain|describe|meaning|means|purpose|risk|threat|attack|hijack|"
    r"vulnerab\w*|mitigat\w+|countermeasure|recommend\w*|impact|procedure|algorithm|"
    r"pseudo\s*code|steps?|guidance|best practice|should|protect|secure|exploit)\b",
    re.I,
)

# "What is X" is a definition. "What CAP versions" is a lookup.
_DEFINITIONAL = re.compile(r"^\s*(what\s+is|what\s+are|explain|define)\b", re.I)

_LOOKUP = re.compile(
    r"\b(list|which|what|show|give)\b.*\b("
    r"all|every|address|addresses|gt|gts|value|values|version|versions|"
    r"code|codes|range|ranges|node|nodes|contact|contacts|number|numbers|"
    r"supported|support"
    r")\b",
    re.I,
)

_STRONG_MATCH = 6.0

# Message-policy / category taxonomy — not IR.21 operator table lookups.
_POLICY_PROHIBIT = re.compile(
    r"\b(prohibit\w*|forbidden|never\s+accept|cat\s*1|category[-\s]?1)\b",
    re.I,
)
_POLICY_MESSAGES = re.compile(
    r"\b(which|what)\s+\w*\s*messages?\s+(are|is)\b",
    re.I,
)
_POLICY_VALIDATE = re.compile(
    r"\b(validat\w+|parameters?)\b",
    re.I,
)
_POLICY_ULR = re.compile(
    r"\b(updatelocation(?:request)?|update\s+location|\bulr\b)\b",
    re.I,
)
_POLICY_CATEGORY = re.compile(
    r"\b(category[-\s]?3\.1|category[-\s]?3\.2|cat[-\s]?3\.1|cat[-\s]?3\.2|"
    r"category[-\s]?2|category[-\s]?3)\b",
    re.I,
)
_POLICY_CATEGORY_DIFF = re.compile(
    r"\bdifference\s+between\s+category\b",
    re.I,
)


def is_standards_knowledge_query(query: str) -> bool:
    """True when FS / standards prose should lead — not policy tables or IR.21."""
    from app.agent.knowledge_domains import is_standards_knowledge_query as _is_std

    return _is_std(query)


def is_policy_led_query(query: str) -> bool:
    """True when message_policy / taxonomy should lead — not IR.21 roaming tables."""
    q = query or ""
    if _POLICY_PROHIBIT.search(q):
        return True
    if _POLICY_MESSAGES.search(q) and re.search(
        r"\b(ss7|map|diameter|signaling|signalling|prohibit|forbidden|cat\s*1)\b", q, re.I
    ):
        return True
    if _POLICY_VALIDATE.search(q) and _POLICY_ULR.search(q):
        return True
    if _POLICY_CATEGORY_DIFF.search(q):
        return True
    if len(_POLICY_CATEGORY.findall(q)) >= 2:
        return True
    return False


@dataclass
class Route:
    route: str
    structured_score: float = 0.0
    tables: list[str] = field(default_factory=list)
    matched_terms: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def uses_structured(self) -> bool:
        return self.route in (STRUCTURED, HYBRID)

    @property
    def uses_documents(self) -> bool:
        return self.route in (KNOWLEDGE, HYBRID)

    def as_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "structured_score": round(self.structured_score, 2),
            "tables": self.tables,
            "matched_terms": self.matched_terms,
            "reason": self.reason,
        }


def choose_route(query: str) -> Route:
    """Pick the retrieval mechanism for a question."""
    if is_standards_knowledge_query(query):
        return Route(
            KNOWLEDGE,
            reason="standards/theory question; answer from FS specification corpus not policy or IR.21",
        )

    try:
        from ir21.retrieval import search
    except Exception:
        return Route(KNOWLEDGE, reason="structured store unavailable")

    try:
        hits = search(query)
    except Exception:
        return Route(KNOWLEDGE, reason="structured store unreachable")

    if not hits:
        return Route(KNOWLEDGE, reason="no structured record matches the question")

    score = max(h.score for h in hits)
    tables = [h.spec.table for h in hits]
    terms = sorted({t for h in hits for t in h.matched})
    if is_standards_knowledge_query(query):
        return Route(
            KNOWLEDGE,
            score,
            tables,
            terms,
            "standards/theory question; answer from FS specification corpus not policy or IR.21",
        )
    if is_policy_led_query(query):
        return Route(
            KNOWLEDGE,
            score,
            tables,
            terms,
            "message-policy or category taxonomy question; IR.21 roaming match is incidental",
        )

    explanatory = bool(_EXPLANATORY.search(query or ""))
    definitional = bool(_DEFINITIONAL.search(query or ""))
    lookup = bool(_LOOKUP.search(query or ""))

    if definitional and not lookup:
        return Route(
            KNOWLEDGE,
            score,
            tables,
            terms,
            "definitional question answered from the document corpus",
        )
    if explanatory:
        # A single generic word overlapping a stored value is not enough to pull
        # operator records into a question about how something works — that only
        # distracts the answer model from the specification text.
        if score < _STRONG_MATCH:
            return Route(
                KNOWLEDGE,
                score,
                tables,
                terms,
                "explanatory question with only an incidental structured match",
            )
        return Route(
            HYBRID,
            score,
            tables,
            terms,
            "question asks for explanation and names stored values",
        )
    if score >= _STRONG_MATCH or lookup:
        return Route(
            STRUCTURED,
            score,
            tables,
            terms,
            "question asks for documented values held in the structured store",
        )
    if score < 4.0:
        return Route(KNOWLEDGE, score, tables, terms, "structured match too weak; using documents")
    return Route(HYBRID, score, tables, terms, "weak structured match; consulting both sources")
