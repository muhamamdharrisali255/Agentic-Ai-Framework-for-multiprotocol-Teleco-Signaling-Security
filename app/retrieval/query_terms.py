"""Query term analysis shared by retrieval rerankers.

Ranking must be driven by what the user actually asked. Soft expansions come from
taxonomy aliases + morphology. Definition boost/demote patterns live in
data/taxonomy/telecom_security.json → retrieval_hints (not hardcoded FS.21 regex).
"""

from __future__ import annotations

import re
from functools import lru_cache

_SOFT_TERMS = frozenset({
    "what", "which", "does", "do", "the", "are", "is", "and", "for", "from",
    "with", "list", "all", "show", "give", "find", "any", "that", "this",
    "document", "documents", "table", "tables", "rows", "row", "section",
    "sections", "page", "pages", "support", "supported", "supports", "listed",
    "include", "includes", "including", "each", "every", "explicit", "cite",
    "info", "information", "version", "versions", "please", "about", "there",
    "used", "to", "an", "a", "of", "in", "on", "both", "relevant",
})

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[/-][A-Za-z0-9]+)*")
_VALUE_RE = re.compile(r"\d")
_CAMEL_RE = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

_VALIDATE_INTENT = re.compile(
    r"\b(parameter|parameters|validat\w*|validation\s+fields?|checklist|check)\b",
    re.I,
)
_ATTACK_INTENT = re.compile(
    r"\b(attack|threat|exploit|hijack|dos|denial.of.service|risk\s+class)\b",
    re.I,
)
_ATTACK_NARRATIVE = re.compile(
    r"risk classification|avp risk|attack scenario|denial of service|"
    r"dos against|summary of attacks",
    re.I,
)
_VALIDATE_NARRATIVE = re.compile(
    r"\b(validation|filtering|checklist|parameter|validation_fields|"
    r"category\s*2|cat2)\b",
    re.I,
)
_DEFINITION_INTENT = re.compile(
    r"\b(what\s+is|what\s+are|define|definition\s+of|meaning\s+of)\b",
    re.I,
)
_CAT_ASK = re.compile(
    r"\b(category|cat)[-\s]?([123](?:\.\d)?)\b",
    re.I,
)


def soft_terms() -> frozenset[str]:
    return _SOFT_TERMS


def _with_singular(terms: set[str]) -> set[str]:
    out = set(terms)
    for t in terms:
        if len(t) > 2 and t.endswith("s") and not t.endswith("ss"):
            out.add(t[:-1])
    return out


def query_tokens(query: str) -> set[str]:
    toks = {t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 3}
    return _with_singular(toks)


def hard_terms(query: str) -> set[str]:
    toks = {t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 4}
    return _with_singular({t for t in toks if t not in _SOFT_TERMS})


def key_identifiers(query: str) -> set[str]:
    out: set[str] = set()
    for tok in _TOKEN_RE.findall(query or ""):
        if len(tok) > 12:
            continue
        looks_acronym = tok != tok.lower() and tok != tok.title()
        if looks_acronym or _VALUE_RE.search(tok):
            out.add(tok.lower())
            out.add(re.sub(r"[/-]", "", tok).lower())
    return {t for t in _with_singular(out) if len(t) >= 2}


def wants_values(query: str) -> bool:
    return bool(
        re.search(
            r"\b(version|versions|value|values|list|which|what|address|addresses|"
            r"number|numbers|code|codes|range|ranges|gt|gts|supported)\b",
            (query or "").lower(),
        )
    )


def phrase_variants(phrase: str) -> list[str]:
    """Morphological variants of a phrase (spaced / compact / hyphen)."""
    raw = (phrase or "").strip()
    if not raw:
        return []
    spaced = _CAMEL_RE.sub(" ", raw).replace("_", " ").replace("-", " ")
    spaced = re.sub(r"\s+", " ", spaced).strip()
    compact = re.sub(r"[\s_-]+", "", spaced)
    hyphen = spaced.replace(" ", "-")
    out: list[str] = []
    for form in (raw, spaced, compact, hyphen):
        if form and form not in out:
            out.append(form)
    return out


@lru_cache(maxsize=1)
def _retrieval_hints() -> dict:
    try:
        from app.ontology.taxonomy import load_taxonomy

        return dict((load_taxonomy() or {}).get("retrieval_hints") or {})
    except Exception:
        return {}


def _asked_category_meta(query: str) -> dict | None:
    """Return taxonomy meta for the Category-N named in the query."""
    try:
        from app.ontology.taxonomy import load_taxonomy

        cats = (load_taxonomy() or {}).get("roaming_categories") or {}
    except Exception:
        return None
    q = (query or "").lower()
    # Prefer longer keys (3.1 before 3).
    items: list[tuple[str, dict]] = []
    for cat, meta in cats.items():
        items.append((cat, meta or {}))
        for sub, submeta in ((meta or {}).get("children") or {}).items():
            items.append((sub, submeta or {}))
    items.sort(key=lambda kv: -len(kv[0]))
    for cat, meta in items:
        cl = cat.lower()
        cat_num = cl.replace("cat", "")
        if (
            cl in q
            or f"category {cat_num}" in q
            or f"category-{cat_num}" in q
            or f"category {cat_num}." in q
        ):
            return {"term": cat, **meta}
    return None


def intent_expansion_terms(query: str) -> list[str]:
    """Soft expansions from taxonomy aliases + category definition_sections."""
    q = (query or "").lower()
    terms: list[str] = []

    try:
        from app.ontology.taxonomy import load_taxonomy

        aliases = (load_taxonomy() or {}).get("aliases") or {}
    except Exception:
        aliases = {}

    for alias, canon in sorted(aliases.items(), key=lambda kv: -len(str(kv[0]))):
        al = str(alias).lower().strip()
        can = str(canon).strip()
        if not al or not can:
            continue
        if len(al) <= 4:
            if not re.search(rf"\b{re.escape(al)}\b", q):
                continue
        elif al not in q:
            continue
        for form in phrase_variants(can):
            if form.lower() not in q and form not in terms:
                terms.append(form)

    for tok in _TOKEN_RE.findall(query or ""):
        if len(tok) < 6 or tok.islower() or tok.isupper():
            continue
        for form in phrase_variants(tok):
            if form.lower() not in q and form not in terms:
                terms.append(form)

    if _VALIDATE_INTENT.search(q) and not _ATTACK_INTENT.search(q):
        for t in ("validation_fields", "filtering"):
            if t.lower() not in q and t not in terms:
                terms.append(t)

    # Definition / category ASK → label + definition_sections from taxonomy.
    if _DEFINITION_INTENT.search(q) or _CAT_ASK.search(q):
        meta = _asked_category_meta(query)
        if meta:
            label = str(meta.get("label") or "").strip()
            if label and label.lower() not in q and label not in terms:
                terms.append(label)
            for sec in meta.get("definition_sections") or []:
                s = str(sec).strip()
                if s and s not in terms:
                    terms.append(s)
            src = str(meta.get("source") or "")
            m = re.search(r"§\s*([\d.]+)", src)
            if m and m.group(1) not in terms:
                terms.append(m.group(1))
            if "Application Packet Categorisation" not in terms:
                terms.append("Application Packet Categorisation")

    return terms[:12]


def _wants_definition(query: str) -> bool:
    q = query or ""
    return bool(
        _DEFINITION_INTENT.search(q)
        or (_CAT_ASK.search(q) and re.search(r"\b(what|define|definition|meaning|message)\b", q, re.I))
    )


def intent_alignment_score(blob: str, query: str) -> float:
    """Soft re-rank: overlap with mapped query terms + taxonomy retrieval_hints."""
    q = (query or "").lower()
    b = (blob or "").lower()
    if not q or not b:
        return 0.0

    score = 0.0
    content = hard_terms(query) | key_identifiers(query)
    for phrase in intent_expansion_terms(query):
        content |= hard_terms(phrase)
        pl = phrase.lower()
        if len(pl) >= 4 and pl in b:
            score += 2.5

    score += sum(1.2 for t in content if len(t) >= 3 and t in b)

    for direction in ("inbound", "outbound"):
        if direction in q and direction in b:
            score += 1.5

    if _VALIDATE_INTENT.search(q) and not _ATTACK_INTENT.search(q):
        if _VALIDATE_NARRATIVE.search(b):
            score += 2.5
        if _ATTACK_NARRATIVE.search(b):
            score -= 5.0

    if _wants_definition(query):
        hints = _retrieval_hints()
        boosts = [str(p).lower() for p in (hints.get("definition_boost_patterns") or [])]
        demotes = [str(p).lower() for p in (hints.get("definition_demote_patterns") or [])]
        if any(p in b for p in boosts):
            score += 6.0
        if any(p in b for p in demotes) and not any(p in b for p in boosts):
            score -= 6.0
        if "table of contents" in b:
            score -= 8.0
        # Prefer sections listed on the asked category.
        meta = _asked_category_meta(query)
        if meta:
            for sec in meta.get("definition_sections") or []:
                if str(sec).lower() in b:
                    score += 3.0
            num = str(meta.get("term") or "").lower().replace("cat", "")
            if num and re.search(rf"category\s*{re.escape(num)}|cat\s*{re.escape(num)}", b):
                score += 2.0

    return score


def clear_retrieval_hint_cache() -> None:
    _retrieval_hints.cache_clear()
