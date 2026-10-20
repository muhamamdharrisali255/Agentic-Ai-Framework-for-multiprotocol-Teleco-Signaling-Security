"""Telecom security taxonomy — classification for retrieval filtering (§3.1)."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config.settings import settings

_TAXONOMY_PATH = settings.project_root / "data" / "taxonomy" / "telecom_security.json"


@lru_cache(maxsize=1)
def load_taxonomy() -> dict[str, Any]:
    if not _TAXONOMY_PATH.exists():
        return {}
    return json.loads(_TAXONOMY_PATH.read_text(encoding="utf-8"))


def _category_definition(meta: dict[str, Any]) -> str:
    """FS-aligned definition text with optional source citation."""
    label = str(meta.get("label") or "").strip()
    desc = str(meta.get("description") or "").strip()
    src = str(meta.get("source") or "").strip()
    if label and desc:
        text = f"{label}: {desc}"
    else:
        text = label or desc
    if src:
        text = f"{text} [{src}]"
    return text


def _canonical_row(term: str, meta: dict[str, Any], *, domain: str = "category") -> dict[str, str]:
    return {
        "term": term,
        "definition": _category_definition(meta),
        "domain": domain,
        "source": str(meta.get("source") or ""),
    }


def reload_taxonomy() -> dict[str, Any]:
    load_taxonomy.cache_clear()
    return load_taxonomy()


def taxonomy_terms() -> list[dict[str, str]]:
    """Flatten taxonomy into dictionary-style rows for the dictionary worker."""
    tax = load_taxonomy()
    rows: list[dict[str, str]] = []
    by_term: dict[str, dict[str, str]] = {}

    def add(row: dict[str, str]) -> None:
        term = str(row.get("term") or "").strip()
        if not term:
            return
        key = term.lower()
        if key not in by_term:
            by_term[key] = row
            rows.append(row)

    for proto, children in (tax.get("protocols") or {}).items():
        add({
            "term": proto,
            "definition": f"Telecom signalling protocol ({', '.join(children)})",
            "domain": "protocol",
            "source": "",
        })
        for child in children:
            add({
                "term": child,
                "definition": f"{proto} application / interface",
                "domain": "protocol",
                "source": "",
            })

    for cat, meta in (tax.get("roaming_categories") or {}).items():
        add(_canonical_row(cat, meta))
        label = str(meta.get("label") or cat)
        if label.lower() != cat.lower():
            add({
                "term": label,
                "definition": _category_definition(meta),
                "domain": "category",
                "source": str(meta.get("source") or ""),
            })
        for sub, submeta in (meta.get("children") or {}).items():
            add(_canonical_row(sub, submeta))
            sub_label = str(submeta.get("label") or sub)
            if sub_label.lower() != sub.lower():
                add({
                    "term": sub_label,
                    "definition": _category_definition(submeta),
                    "domain": "category",
                    "source": str(submeta.get("source") or ""),
                })

    for obj in tax.get("attack_objectives") or []:
        add({"term": obj, "definition": f"Attack objective: {obj}", "domain": "attack_objective", "source": ""})

    for alias, canon in (tax.get("aliases") or {}).items():
        canon_row = by_term.get(str(canon).lower())
        if not canon_row:
            continue
        add({
            "term": alias,
            "definition": canon_row["definition"],
            "domain": "alias",
            "source": canon_row.get("source", ""),
        })
        if len(alias) <= 6:
            add({
                "term": alias.upper(),
                "definition": canon_row["definition"],
                "domain": "alias",
                "source": canon_row.get("source", ""),
            })

    return rows


def categories_for_query(query: str) -> list[str]:
    """Return CAT* labels mentioned or implied by the question."""
    q = (query or "").lower()
    out: list[str] = []

    # Prefer specific subtypes, then CAT1/2/3. Accept CAT-2, Cat.2, category 2, cat2.
    _cat_patterns: list[tuple[str, str]] = [
        (r"\bcat(?:egory)?[-\s.]?3\.1\b|\bcat3\.1\b", "CAT3.1"),
        (r"\bcat(?:egory)?[-\s.]?3\.2\b|\bcat3\.2\b", "CAT3.2"),
        (r"\bcat(?:egory)?[-\s.]?1\b|\bcat1\b", "CAT1"),
        (r"\bcat(?:egory)?[-\s.]?2\b|\bcat2\b", "CAT2"),
        (r"\bcat(?:egory)?[-\s.]?3\b|\bcat3\b", "CAT3"),
    ]
    for pat, label in _cat_patterns:
        if re.search(pat, q):
            if label == "CAT3" and ("CAT3.1" in out or "CAT3.2" in out):
                continue
            out.append(label)

    if "prohibit" in q:
        out.append("CAT1")
    if "hijack" in q or "abuse" in q or "fraud" in q:
        out.extend(["CAT2", "CAT3.2"])
    if "sequence" in q or "followed by" in q or ("air" in q and "ulr" in q):
        out.append("CAT3.1")
    seen: set[str] = set()
    ordered: list[str] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def protocols_for_query(query: str) -> list[str]:
    q = (query or "").lower()
    tax = load_taxonomy()
    found: list[str] = []
    for proto, children in (tax.get("protocols") or {}).items():
        pl = proto.lower()
        if len(pl) <= 4:
            if re.search(rf"\b{re.escape(pl)}\b", q):
                found.append(proto)
        elif pl in q:
            found.append(proto)
        for child in children:
            cl = child.lower()
            if len(cl) <= 4:
                if re.search(rf"\b{re.escape(cl)}\b", q):
                    found.append(child)
            elif cl in q:
                found.append(child)
    return list(dict.fromkeys(found))


def expand_message_alias(token: str) -> str:
    tax = load_taxonomy()
    aliases = {k.lower(): v for k, v in (tax.get("aliases") or {}).items()}
    return aliases.get((token or "").lower(), token)


def resolve_query_terms(query: str) -> list[dict[str, str]]:
    """Map phrases in the question to taxonomy definitions (for dictionary agent)."""
    q = (query or "").lower()
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in taxonomy_terms():
        term = str(row.get("term") or "")
        if len(term) < 2:
            continue
        key = term.lower()
        if key in seen:
            continue
        if key in q or (len(term) >= 3 and term.upper() in (query or "").upper() and term.isupper()):
            hits.append(row)
            seen.add(key)
        if len(hits) >= 10:
            break
    # Ensure resolved aliases for category-N phrases even if term list order missed them
    for alias, canon in (load_taxonomy().get("aliases") or {}).items():
        if alias.lower() in q and canon not in seen:
            for row in taxonomy_terms():
                if row.get("term") == canon:
                    hits.append(row)
                    seen.add(canon)
                    break
    return hits[:10]


def metadata_filters_for_query(query: str) -> dict[str, Any]:
    """Soft taxonomy hints for ranking — NOT hard Qdrant/FAISS filters (§4.1 / §7.2)."""
    return taxonomy_soft_hints(query)


# Protocol → primary detailed FS spec. FS.21 is the cross-protocol umbrella only.
_FS_PRIMARY: dict[str, str] = {
    "SS7": "FS.11",
    "MAP": "FS.11",
    "Diameter": "FS.19",
    "S6a": "FS.19",
    "GTP": "FS.20",
    "GTP-C": "FS.20",
    "GTP-U": "FS.20",
}

_FS_PROTOCOL_DOCS: dict[str, list[str]] = {
    "SS7": ["FS.11", "FS.21"],
    "MAP": ["FS.11", "FS.21"],
    "Diameter": ["FS.19", "FS.21"],
    "S6a": ["FS.19", "FS.21"],
    "GTP": ["FS.20", "FS.21"],
    "GTP-C": ["FS.20", "FS.21"],
    "GTP-U": ["FS.20", "FS.21"],
}

_ALL_FS = ("FS.11", "FS.19", "FS.20", "FS.21", "FS.22")
_PROTOCOL_PRIMARIES = frozenset({"FS.11", "FS.19", "FS.20"})


def primary_fs_document(query: str) -> str:
    """Single detailed FS primary for this question (empty if cross-protocol / category-only)."""
    preferred = fs_documents_for_query(query)
    if not preferred:
        return ""
    if preferred[0] in _PROTOCOL_PRIMARIES:
        return preferred[0]
    return ""


def fs_documents_for_query(query: str) -> list[str]:
    """Map query → FS docs in priority order. Protocol primary ALWAYS before FS.21."""
    q = (query or "").lower()
    preferred: list[str] = []
    seen: set[str] = set()

    def add(doc: str) -> None:
        key = doc.upper()
        if key not in seen:
            seen.add(key)
            preferred.append(key)

    # Protocol signals first — detailed specs beat the FS.21 umbrella.
    for proto in protocols_for_query(query):
        primary = _FS_PRIMARY.get(proto)
        if primary:
            add(primary)

    def _has(tok: str) -> bool:
        if len(tok) <= 4 and " " not in tok:
            return bool(re.search(rf"\b{re.escape(tok)}\b", q))
        return tok in q

    if any(_has(tok) for tok in ("diameter", "s6a", "ulr", "air", "ula", "origin-host", "origin-realm", "command-code")):
        add("FS.19")
    if any(_has(tok) for tok in ("gtp", "create session", "gtp-c", "pdn", "teid", "apn", "bearer")):
        add("FS.20")
    if any(
        _has(tok)
        for tok in (
            "ss7", "map", "sccp", "global title", "sendroutinginfo",
            "provide roaming", "ati", "psi", "sai", "any time interrogation",
        )
    ):
        add("FS.11")

    aliases = load_taxonomy().get("aliases") or {}
    for alias, canon in aliases.items():
        al = alias.lower()
        # Short aliases need word boundaries ("air" must not match "authentication").
        if len(al) <= 4:
            if not re.search(rf"\b{re.escape(al)}\b", q):
                continue
        elif al not in q:
            continue
        if al in ("ulr", "air", "ula"):
            add("FS.19")
        elif al in ("csr",):
            add("FS.20")
        elif al in ("sai", "ati"):
            add("FS.11")

    cats = categories_for_query(query)
    # CAT3.1/3.2 detail lives in FS.19; CAT1/2 definitions live in FS.21.
    if any(c in ("CAT3.1", "CAT3.2") for c in cats):
        add("FS.19")
    if any(c in ("CAT1", "CAT2", "CAT3") for c in cats) and not preferred:
        add("FS.21")

    # Umbrella only after a protocol primary (or alone for pure category Qs).
    if preferred and preferred[0] in _PROTOCOL_PRIMARIES:
        add("FS.21")
    elif not preferred:
        if re.search(r"\bcat(?:egory)?[-\s]?[123]", q) or "prohibit" in q:
            add("FS.21")
        elif any(tok in q for tok in ("interconnect", "roaming", "signalling", "signaling", "security")):
            preferred.extend(["FS.19", "FS.20", "FS.21"])

    # Re-order: protocol primaries first, FS.21 last among preferred.
    primaries = [d for d in preferred if d in _PROTOCOL_PRIMARIES]
    umbrella = [d for d in preferred if d == "FS.21"]
    other = [d for d in preferred if d not in _PROTOCOL_PRIMARIES and d != "FS.21"]
    return primaries + other + umbrella


def demoted_fs_documents_for_query(query: str) -> list[str]:
    """FS docs to deprioritize. When a protocol primary is known, demote FS.21 hard."""
    preferred = fs_documents_for_query(query)
    if not preferred:
        return []
    primary = preferred[0]
    demote: list[str] = []
    for doc in _ALL_FS:
        if doc == primary:
            continue
        # Protocol-specific question → FS.21 is secondary only (demote relative to primary).
        if primary in _PROTOCOL_PRIMARIES and doc == "FS.21":
            demote.append(doc)
            continue
        if doc not in preferred:
            demote.append(doc)
    return demote


def query_augmentation_terms(query: str) -> list[str]:
    """Single soft expansion API: protocols + categories + alias/morphology map.

    Used by QueryEnhancer once. Never pins a PDF. Never injects answer fields.
    """
    from app.retrieval.query_terms import intent_expansion_terms

    q = (query or "").lower()
    terms: list[str] = []
    protos = protocols_for_query(query)
    if "SS7" in protos or "MAP" in protos:
        terms.extend(["SS7", "MAP", "SCCP"])
    if "Diameter" in protos or "S6a" in protos:
        terms.extend(["Diameter", "S6a"])
    if any(p.startswith("GTP") for p in protos):
        terms.append("GTP-C")

    tax = load_taxonomy()
    for cat, meta in (tax.get("roaming_categories") or {}).items():
        cl = cat.lower()
        cat_num = cl.replace("cat", "")
        if cl in q or f"category {cat_num}" in q or f"category-{cat_num}" in q:
            label = str((meta or {}).get("label") or "").strip()
            if label and label.lower() not in q:
                terms.append(label)
            if cat not in terms:
                terms.append(cat)

    terms.extend(intent_expansion_terms(query))
    out: list[str] = []
    for t in terms:
        if t.lower() not in q and t not in out:
            out.append(t)
    return out[:12]


def taxonomy_soft_hints(query: str) -> dict[str, Any]:
    """Facets used as boosts in hybrid_search / rerank, never as exclusive filters."""
    cats = categories_for_query(query)
    protos = protocols_for_query(query)
    hints: dict[str, Any] = {}
    if cats:
        hints["taxonomy_categories"] = cats
        hints["categories"] = cats
    if protos:
        hints["taxonomy_protocols"] = protos
        hints["protocols"] = protos
    fs_docs = fs_documents_for_query(query)
    if fs_docs:
        hints["preferred_fs_docs"] = fs_docs
    primary = primary_fs_document(query)
    if primary:
        hints["primary_fs_doc"] = primary
    demoted = demoted_fs_documents_for_query(query)
    if demoted:
        hints["demoted_fs_docs"] = demoted
    aug = query_augmentation_terms(query)
    if aug:
        hints["augmentation_terms"] = aug
    return hints
