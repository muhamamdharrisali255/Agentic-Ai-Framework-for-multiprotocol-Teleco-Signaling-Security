"""Query Enhancement — map user wording via dictionary + taxonomy (once).

Soft understanding only. Original query is always preserved; expansions append
search terms for Qdrant similarity. Never invents answers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.config.settings import settings
from app.nlp import domain_dictionary as domain_dict


@dataclass
class DictionaryTerm:
    term: str
    definition: str
    domain: str = ""
    aliases: list[str] = field(default_factory=list)


@dataclass
class EnhancedQuery:
    original_query: str
    enhanced_query: str
    expanded_terms: list[DictionaryTerm] = field(default_factory=list)


_DEF_WORD = re.compile(r"[A-Za-z][A-Za-z0-9./_-]{2,}")


def _definition_search_hints(definition: str, *, limit: int = 3) -> list[str]:
    stop = {
        "the", "and", "for", "with", "from", "that", "this", "are", "is", "was",
        "were", "been", "being", "have", "has", "had", "not", "but", "also",
        "used", "using", "into", "over", "under", "when", "where", "which",
        "their", "they", "them", "than", "then", "such", "only", "more",
        "application", "packets", "packet", "network", "networks", "message",
        "messages", "information",
    }
    out: list[str] = []
    for w in _DEF_WORD.findall(definition or ""):
        low = w.lower()
        if low in stop or len(low) < 4:
            continue
        if w not in out and low not in {x.lower() for x in out}:
            out.append(w)
        if len(out) >= limit:
            break
    return out


def _phrase_dictionary_hits(query: str, *, limit: int = 6) -> list[dict]:
    q = (query or "").lower()
    if not q:
        return []
    scored: list[tuple[int, dict]] = []
    for row in domain_dict.load_terms():
        term = str(row.get("term") or "").strip()
        if not term:
            continue
        best = 0
        for c in [term] + [str(a) for a in (row.get("aliases") or []) if a]:
            cl = c.lower().strip()
            if len(cl) < 2:
                continue
            if len(cl) <= 4:
                if re.search(rf"\b{re.escape(cl)}\b", q):
                    best = max(best, len(cl) + 10)
            elif cl in q:
                best = max(best, len(cl))
        if best:
            scored.append((best, row))
    scored.sort(key=lambda x: -x[0])
    out: list[dict] = []
    seen: set[str] = set()
    for _, row in scored:
        key = str(row.get("term") or "").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
        if len(out) >= limit:
            break
    return out


class QueryEnhancer:
    """Map user query → dictionary terms + taxonomy augmentation (single pass)."""

    def __init__(self, max_expansions: int | None = None) -> None:
        self._max = max_expansions or settings.query_enhancement_max_expansions

    def enhance(self, query: str) -> EnhancedQuery:
        original = (query or "").strip()
        if not original:
            return EnhancedQuery(original_query="", enhanced_query="")

        tokens = [t for t in re.split(r"\W+", original) if len(t) >= 2]
        rows = domain_dict.expand_tokens(tokens, limit=self._max)
        for row in _phrase_dictionary_hits(original, limit=self._max):
            key = str(row.get("term") or "").lower()
            if key and not any(str(r.get("term") or "").lower() == key for r in rows):
                rows.append(row)
            if len(rows) >= self._max:
                break

        expanded: list[DictionaryTerm] = []
        append_parts: list[str] = []
        for match in rows[: self._max]:
            dt = DictionaryTerm(
                term=match["term"],
                definition=match.get("definition") or "",
                domain=match.get("domain") or "",
                aliases=list(match.get("aliases") or []),
            )
            expanded.append(dt)
            append_parts.append(dt.term)
            for alias in (dt.aliases or [])[:2]:
                a = str(alias).strip()
                if a and a.lower() != dt.term.lower() and len(a) <= 40:
                    append_parts.append(a)
            append_parts.extend(_definition_search_hints(dt.definition))

        # Single taxonomy augmentation (aliases + protocols + categories + morphology).
        try:
            from app.ontology.taxonomy import query_augmentation_terms

            append_parts.extend(query_augmentation_terms(original))
        except Exception:
            pass

        enhanced = original
        if append_parts:
            enhanced = f"{original} {' '.join(dict.fromkeys(append_parts))}"

        return EnhancedQuery(
            original_query=original,
            enhanced_query=enhanced,
            expanded_terms=expanded,
        )


def dictionary_understanding_block(expanded_terms: list[dict] | list[DictionaryTerm] | None) -> str:
    """Glossary for the LLM — understanding aids, not the answer."""
    if not expanded_terms:
        return ""
    lines: list[str] = []
    for item in expanded_terms[:6]:
        if isinstance(item, DictionaryTerm):
            term, definition = item.term, item.definition
        else:
            term = str(item.get("term") or "").strip()
            definition = str(item.get("definition") or "").strip()
        if not term or not definition:
            continue
        def_short = definition if len(definition) <= 220 else definition[:217] + "…"
        lines.append(f"- {term}: {def_short}")
    if not lines:
        return ""
    return (
        "[Query understanding — dictionary/taxonomy map; not the answer]\n"
        + "\n".join(lines)
        + "\n[/Query understanding]\n"
    )


def get_query_enhancer() -> QueryEnhancer:
    return QueryEnhancer()
