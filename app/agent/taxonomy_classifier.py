"""Query-time taxonomy facet classifier — §4.1 imoplementation_plan_updated.md.

Maps analyst questions onto protocol / category / attack_type facets for soft
ranking boosts in RRF/rerank — never as hard filters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.ontology.taxonomy import (
    categories_for_query,
    load_taxonomy,
    protocols_for_query,
)


@dataclass
class TaxonomyFacets:
    protocol: str = ""
    category: str = ""
    attack_type: str = ""
    categories: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    preferred_fs_docs: list[str] = field(default_factory=list)
    demoted_fs_docs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        primary = ""
        if self.preferred_fs_docs and self.preferred_fs_docs[0] in ("FS.11", "FS.19", "FS.20"):
            primary = self.preferred_fs_docs[0]
        return {
            "protocol": self.protocol,
            "category": self.category,
            "attack_type": self.attack_type,
            "categories": self.categories,
            "protocols": self.protocols,
            "preferred_fs_docs": self.preferred_fs_docs,
            "demoted_fs_docs": self.demoted_fs_docs,
            "primary_fs_doc": primary,
        }

    def match_score(self, item: dict[str, Any]) -> float:
        """Soft boost: count overlapping facets in evidence metadata/body."""
        blob = " ".join(
            str(item.get(k) or "")
            for k in ("body", "text", "section", "source", "category", "protocol", "attack_objective")
        ).lower()
        meta = item.get("metadata") or {}
        if isinstance(meta, dict):
            blob += " " + " ".join(str(v) for v in meta.values()).lower()

        score = 0.0
        for cat in self.categories:
            if cat.lower() in blob or cat.replace(".", "").lower() in blob:
                score += 1.2
        if self.category and self.category.lower() in blob:
            score += 1.5
        for proto in self.protocols:
            if proto.lower() in blob:
                score += 1.0
        if self.protocol and self.protocol.lower() in blob:
            score += 1.2
        if self.attack_type:
            at = self.attack_type.lower()
            if at in blob or at.replace(" ", "-") in blob:
                score += 1.3
        for i, fs_doc in enumerate(self.preferred_fs_docs):
            if fs_doc.lower() in blob:
                if fs_doc.upper() == "FS.21" and self.preferred_fs_docs and self.preferred_fs_docs[0] in (
                    "FS.11", "FS.19", "FS.20"
                ):
                    score += 1.0
                else:
                    score += 8.0 - (i * 1.2)
        primary = ""
        if self.preferred_fs_docs and self.preferred_fs_docs[0] in ("FS.11", "FS.19", "FS.20"):
            primary = self.preferred_fs_docs[0]
        if primary and primary.lower() in blob:
            score += 10.0
        for fs_doc in self.demoted_fs_docs:
            if fs_doc.lower() in blob:
                score -= 12.0 if (fs_doc.upper() == "FS.21" and primary) else 9.0
        return score


_BLOCK_RE = re.compile(
    r"\b(block\s+all|enforce|deploy|draft|create)\b.*\b(cat|category|ss7|diameter|gtp|abuse|attack)\b",
    re.I,
)


def classify_taxonomy_facets(query: str) -> TaxonomyFacets:
    """Lightweight classifier — regex + taxonomy helpers, no LLM."""
    from app.ontology.taxonomy import demoted_fs_documents_for_query, fs_documents_for_query

    q = query or ""
    cats = categories_for_query(q)
    protos = protocols_for_query(q)
    attack_type = _attack_type_for_query(q)
    preferred = fs_documents_for_query(q)

    return TaxonomyFacets(
        protocol=protos[0] if protos else "",
        category=cats[0] if cats else "",
        attack_type=attack_type,
        categories=cats,
        protocols=protos,
        preferred_fs_docs=preferred,
        demoted_fs_docs=demoted_fs_documents_for_query(q),
    )


def _attack_type_for_query(query: str) -> str:
    q = (query or "").lower()
    tax = load_taxonomy()
    for obj in tax.get("attack_objectives") or []:
        if obj.lower() in q:
            return obj
    aliases = {
        "location abuse": "Location Manipulation",
        "location manipulation": "Location Manipulation",
        "session abuse": "Unauthorized Session Establishment",
        "apn abuse": "APN/Routing Abuse",
        "authentication probing": "Authentication Vector Acquisition",
        "subscriber probing": "Subscriber Information Acquisition",
        "cross-protocol": "Unauthorized Session Establishment",
    }
    for phrase, canon in aliases.items():
        if phrase in q:
            return canon
    return ""


def is_policy_instruction(query: str) -> bool:
    """True for Case 3 policy commands like 'block all CAT2 messages'."""
    q = (query or "").lower()
    if _BLOCK_RE.search(q):
        return True
    if re.search(r"\bblock\s+all\b", q) and re.search(r"\bcat[-\s.]?\d", q):
        return True
    if "enforce" in q and re.search(r"\bcat[-\s.]?\d|diameter|ss7|gtp\b", q):
        return True
    return False
