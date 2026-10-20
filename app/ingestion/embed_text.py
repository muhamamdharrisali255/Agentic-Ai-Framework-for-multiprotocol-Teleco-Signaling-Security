"""Normalize chunk text before embedding / evidence display.

Keeps Document title + Section breadcrumb in the embedded string (hierarchy
signal for retrieval). Strips volatile page/file lines and Docling markup.
"""

from __future__ import annotations

import os
import re
from typing import Any

_VOLATILE_HEADER = re.compile(
    r"^(?:"
    r"Pages?\s*:|"
    r"Source\s*:|"
    r"File\s*:|"
    r"Table of Contents(?:\s+path)?\s*:"
    r").*$",
    re.I | re.M,
)
_DOCLING_JUNK = re.compile(
    r"(?:self_ref\s*=\s*'?#/[^'\s]+'?"
    r"|meta\s*=\s*None"
    r"|</?body[^>]*>"
    r"|Caption\s*:\s*Figure\s+\d+[^\n]*"
    r"|coord_origin\s*=\s*<[^>\n]+>"
    r"|b=\d+(?:\.\d+)?"
    r"|TOPLEFT|BOTTOMRIGHT)",
    re.I,
)
_MULTI_BLANK = re.compile(r"\n{3,}")
_TOC_SECTION = re.compile(r"^\s*table\s+of\s+contents\b", re.I)


def _index_all_chunks() -> bool:
    try:
        import config

        return bool(getattr(config, "INDEX_ALL_DOCLING_CHUNKS", True))
    except Exception:
        return os.getenv("INDEX_ALL_DOCLING_CHUNKS", "true").lower() in {
            "1",
            "true",
            "yes",
            "on",
        }


def clean_text_for_embedding(text: str, *, section: str | None = None) -> str:
    """Return embeddable text with Document/Section hierarchy retained.

    Strips Pages/Source/File and Docling coordinate junk. Injects a Section
    lead-in from metadata when the body has none.
    """
    raw = (text or "").strip()
    if not raw:
        return ""

    body = _VOLATILE_HEADER.sub("", raw)
    body = _DOCLING_JUNK.sub(" ", body)
    body = _MULTI_BLANK.sub("\n\n", body).strip()
    body = re.sub(r"[ \t]{2,}", " ", body)
    body = _MULTI_BLANK.sub("\n\n", body).strip()

    has_section = bool(re.search(r"^Section\s*:", body, re.I | re.M))
    if not has_section and section:
        section_title = str(section).split("|")[0].strip()
        if section_title and not _TOC_SECTION.match(section_title):
            body = f"Section: {section_title}\n\n{body}".strip()

    return body or raw


def is_indexable_passage(
    text: str,
    *,
    section: str | None = None,
    content_type: str | None = None,
) -> bool:
    """True if the chunk should be embedded.

    With ``INDEX_ALL_DOCLING_CHUNKS=true`` (default), only empty text and pure
    layout/coordinate dumps are rejected — TOC, headings, and short paragraphs
    are kept so the whole document lands in Qdrant.
    """
    cleaned = clean_text_for_embedding(text, section=section)
    if not cleaned:
        return False

    low = cleaned.lower()
    # Pure layout dumps — never useful as retrieval evidence.
    if "coord_origin" in low or "topleft" in low:
        alpha = sum(1 for ch in cleaned if ch.isalpha())
        if alpha < 30:
            return False

    if _index_all_chunks():
        # Keep anything with a few alphanumeric characters.
        useful = sum(1 for ch in cleaned if ch.isalnum())
        return useful >= 8

    # Legacy stricter gate (when INDEX_ALL_DOCLING_CHUNKS=false).
    ct = (content_type or "").lower()
    sec = (section or "").strip()
    alpha = sum(1 for ch in cleaned if ch.isalpha())
    if ct == "toc":
        return len(cleaned) >= 80 and alpha >= 40
    if ct in {"heading", "table", "table_row"}:
        return len(cleaned) >= 40 and alpha >= 20
    if _TOC_SECTION.match(sec.split("|")[0].strip()) and ct not in {"heading", "paragraph"}:
        return False
    if len(cleaned) < 60:
        return False
    if alpha < 40:
        return False
    return True


def is_indexable_chunk(chunk: Any) -> bool:
    """ChunkRecord / payload-aware wrapper around ``is_indexable_passage``."""
    ct = getattr(chunk, "content_type", None)
    ct_val = ct.value if hasattr(ct, "value") else (str(ct) if ct else "")
    text = getattr(chunk, "content", None)
    if text is None and isinstance(chunk, dict):
        text = chunk.get("text") or chunk.get("content") or ""
        ct_val = str(chunk.get("content_type") or ct_val)
        section = str(chunk.get("section") or "")
    else:
        section = str(getattr(chunk, "section", "") or "")
    return is_indexable_passage(str(text or ""), section=section, content_type=ct_val)
