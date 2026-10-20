"""Generic lexical query helpers for BM25 (no protocol/opcode hardfixes)."""

from __future__ import annotations

import re

from app.retrieval.query_terms import soft_terms

# Interrogative / filler words that dilute BM25 without adding recall.
_BM25_STOP = soft_terms() | frozenset(
    {
        "normally", "typically", "usually", "commonly", "generally",
        "associated", "related", "relevant", "regarding", "concerning",
        "please", "explain", "describe", "tell", "me", "how", "why",
        "when", "where", "who", "whom", "whose", "can", "could", "would",
        "should", "may", "might", "also", "into", "onto", "over", "under",
        "between", "among", "via", "per", "vs", "versus",
    }
)

_MESSAGE_LIST_INTENT = re.compile(
    r"(?is)\b(?:"
    r"(?:which|what|list|name|identify)\b.{0,80}\b(?:messages?|commands?|opcodes?|avps?)\b"
    r"|"
    r"\b(?:messages?|commands?)\b.{0,40}\b(?:associated|related|used|relevant)\b"
    r"|"
    r"\btypes?\s+of\b.{0,40}\b(?:messages?|commands?)\b"
    r")",
)

# Structural vocabulary common to signalling message/command tables — not opcodes.
_MESSAGE_TABLE_ANCHORS = (
    "command name",
    "abbreviation",
    "command code",
    "message type",
    "request",
    "response",
    "answer",
)

_FRONT_MATTER_RE = re.compile(
    r"(?is)\b(?:"
    r"copyright(?:\s+notice)?|disclaimer|table\s+of\s+contents|"
    r"document\s+history|foreword|revision\s+history|change\s+history|"
    r"terms\s+and\s+conditions|legal\s+notice"
    r")\b",
)

# Intro/scope distractors that CE often prefers over message inventories.
_WEAK_LIST_SECTION_RE = re.compile(
    r"(?is)\b(?:"
    r"scope|introduction|overview|disclaimer|copyright|"
    r"table\s+of\s+contents|document\s+history"
    r")\b",
)

_MESSAGE_INVENTORY_RE = re.compile(
    r"(?is)\b(?:"
    r"messages?\s+of\s+the|"
    r"list\s+of\s+\w[\w\s/-]{0,40}\s+messages?|"
    r"message\s+type|"
    r"command\s+name|"
    r"belong\s+to\s+the\b.{0,40}\binterface|"
    r"inter-?plmn\s+communication"
    r")\b",
)


def is_message_list_intent(query: str) -> bool:
    """True when the user is asking which messages/commands belong to a topic."""
    return bool(_MESSAGE_LIST_INTENT.search(query or ""))


def content_tokens(query: str) -> list[str]:
    """Lowercased content tokens for BM25 (stopwords removed, order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    low = (query or "").lower()
    # Preserve hyphenated protocol forms as compact tokens (gtp-c → gtpc).
    for compound in re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)+", low):
        compact = compound.replace("-", "")
        if len(compact) >= 2 and compact not in seen and compact not in _BM25_STOP:
            seen.add(compact)
            out.append(compact)
    for tok in re.findall(r"[a-z0-9]+", low):
        if len(tok) < 2 or tok in _BM25_STOP or tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
    return out


def bm25_query_variants(query: str) -> list[str]:
    """Build BM25 query strings: original + cleaned + optional table-anchor variant.

    Message-list questions often use natural language ("normally associated with")
    that matches attack/TOC prose better than command tables. A cleaned content
    query plus generic table-header anchors improves recall without naming
    specific Diameter/GTP opcodes.
    """
    raw = (query or "").strip()
    variants: list[str] = []
    if raw:
        variants.append(raw)

    tokens = content_tokens(raw)
    if tokens:
        cleaned = " ".join(tokens)
        if cleaned.lower() not in {v.lower() for v in variants}:
            variants.append(cleaned)

    if is_message_list_intent(raw) and tokens:
        anchored = " ".join(tokens + list(_MESSAGE_TABLE_ANCHORS))
        if anchored.lower() not in {v.lower() for v in variants}:
            variants.append(anchored)
        # SS7/MAP prohibit / Category-1 inventory wording (helps BM25 hit Annex tables).
        low = raw.lower()
        if any(t in low for t in ("prohibit", "prohibited", "category 1", "cat-1", "cat1", "unauthorised", "unauthorized")):
            cat1 = " ".join(
                tokens
                + [
                    "category 1",
                    "cat.1",
                    "MAP",
                    "opcode",
                    "intra-plmn",
                    "should not be sent",
                ]
            )
            if cat1.lower() not in {v.lower() for v in variants}:
                variants.append(cat1)

    return variants or ([raw] if raw else [])


def is_front_matter_evidence(ev: dict) -> bool:
    """Heuristic demote for copyright / TOC / disclaimer chunks."""
    sec = str(ev.get("section") or "")
    body = str(ev.get("body") or ev.get("text") or "")[:600]
    toc = str(ev.get("toc_path") or "")
    blob = f"{sec}\n{toc}\n{body}"
    if _FRONT_MATTER_RE.search(blob):
        # Keep if the body also carries substantial technical prose beyond the notice.
        technical = re.search(
            r"(?i)\b(diameter|gtp|map|ss7|avp|imsi|hss|mme|category|filtering|"
            r"request|answer|command|message\s+type)\b",
            body,
        )
        if not technical or len(body.strip()) < 200:
            return True
        # Short copyright-only stubs
        if _FRONT_MATTER_RE.search(sec) and len(body.strip()) < 400:
            return True
    return False


def is_weak_message_list_context(ev: dict) -> bool:
    """True for intro/scope prose that is a poor answer to 'which messages…?'."""
    if is_message_inventory(ev) or is_table_like(ev):
        return False
    sec = str(ev.get("section") or "")
    body = str(ev.get("body") or ev.get("text") or "")[:400]
    return bool(_WEAK_LIST_SECTION_RE.search(f"{sec}\n{body}"))


def evidence_key(ev: dict | None, *, chunk_id: str = "", source: str = "") -> str:
    """Stable unique key across documents (chunk_id alone collides FS.11/19/20/21)."""
    if ev:
        cid = str(ev.get("chunk_id") or chunk_id or "")
        doc = str(
            ev.get("document_id")
            or (ev.get("metadata") or {}).get("document_id")
            or ev.get("source")
            or (ev.get("metadata") or {}).get("file_name")
            or source
            or ""
        )
    else:
        cid = str(chunk_id or "")
        doc = str(source or "")
    if not cid:
        return f"{doc}||"
    return f"{doc}||{cid}"


def chunk_record_key(chunk) -> str:
    """Unique key for a ChunkRecord across the multi-document BM25 corpus."""
    doc = str(getattr(chunk, "document_id", None) or getattr(chunk, "file_name", None) or "")
    cid = str(getattr(chunk, "chunk_id", None) or "")
    return f"{doc}||{cid}"


def is_table_like(ev: dict) -> bool:
    ct = str(ev.get("content_type") or "").lower()
    if ct in {"table", "table_row"}:
        return True
    body = str(ev.get("body") or "")
    return bool(
        re.search(
            r"(?i)(?:command\s+name|abbreviation|command\s+code|message\s+type)",
            body,
        )
        and "|" in body
    )


def is_message_inventory(ev: dict) -> bool:
    """Appendix / interface message lists (tables or short inventory prose)."""
    if is_table_like(ev):
        return True
    sec = str(ev.get("section") or "")
    body = str(ev.get("body") or ev.get("text") or "")
    blob = f"{sec}\n{body[:800]}"
    return bool(_MESSAGE_INVENTORY_RE.search(blob))
