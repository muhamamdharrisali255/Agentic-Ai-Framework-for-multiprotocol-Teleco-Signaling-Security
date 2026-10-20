"""Tag chunks with taxonomy facets at ingestion (§4.1 / §7.1)."""

from __future__ import annotations

import re
from typing import Any

from app.ontology.taxonomy import categories_for_query, load_taxonomy, protocols_for_query
from shared.schema import ChunkRecord, ContentType


def infer_chunk_taxonomy(chunk: ChunkRecord) -> dict[str, str]:
    """Derive protocol / category / attack_type metadata from chunk text + headings."""
    blob = " ".join(
        filter(
            None,
            [
                chunk.file_name,
                chunk.section,
                chunk.subsection,
                chunk.toc_path,
                chunk.content[:1200],
            ],
        )
    )
    protos = protocols_for_query(blob)
    cats = categories_for_query(blob)
    attack_type = _attack_type_from_text(blob)

    protocol = protos[0] if protos else _protocol_from_filename(chunk.file_name)
    category = cats[0] if cats else _category_from_text(blob)

    return {
        "protocol": protocol or "",
        "category": category or "",
        "attack_type": attack_type or "",
        "doc_name": _doc_name(chunk.file_name),
        "chunk_type": "table_row" if chunk.content_type == ContentType.TABLE_ROW else "text",
    }


def tag_chunks(chunks: list[ChunkRecord]) -> list[ChunkRecord]:
    """Attach taxonomy facets to each chunk's section metadata for soft retrieval boosts."""
    out: list[ChunkRecord] = []
    for chunk in chunks:
        tags = infer_chunk_taxonomy(chunk)
        section_bits = [chunk.section] if chunk.section else []
        if tags.get("category"):
            section_bits.append(f"category={tags['category']}")
        if tags.get("protocol"):
            section_bits.append(f"protocol={tags['protocol']}")
        if tags.get("attack_type"):
            section_bits.append(f"attack={tags['attack_type']}")
        new_section = " | ".join(dict.fromkeys(s for s in section_bits if s))
        updated = chunk.model_copy(
            update={
                "section": new_section or chunk.section,
                "subsection": tags.get("doc_name") or chunk.subsection,
            }
        )
        out.append(updated)
    return out


def _doc_name(file_name: str) -> str:
    name = file_name or ""
    if "_" in name:
        tail = name.split("_", 1)[1]
        if tail.upper().startswith("FS."):
            return tail
    return name


def _protocol_from_filename(file_name: str) -> str:
    low = (file_name or "").lower()
    if "fs.19" in low or "diameter" in low:
        return "Diameter"
    if "fs.20" in low or "gtp" in low:
        return "GTP"
    if "fs.11" in low or "ss7" in low:
        return "SS7"
    if "fs.21" in low:
        return ""
    if "suricata" in low:
        return ""
    return ""


def _category_from_text(blob: str) -> str:
    low = blob.lower()
    for cat in ("cat3.2", "cat3.1", "cat1", "cat2", "cat3"):
        if cat in low or f"category {cat[-1]}" in low:
            return cat.upper()
    return ""


def _attack_type_from_text(blob: str) -> str:
    low = blob.lower()
    for obj in load_taxonomy().get("attack_objectives") or []:
        if obj.lower() in low:
            return obj
    if "hijack" in low:
        return "Unauthorized Session Establishment"
    if "probing" in low or "authentication vector" in low:
        return "Authentication Vector Acquisition"
    return ""


def taxonomy_boost_score(evidence: dict[str, Any], facets: dict[str, Any]) -> float:
    """Soft boost for RRF/rerank — never excludes chunks."""
    blob = " ".join(
        str(evidence.get(k) or "")
        for k in ("body", "text", "section", "source", "file_name")
    ).lower()
    score = 0.0
    for cat in facets.get("categories") or ([facets.get("category")] if facets.get("category") else []):
        if str(cat).lower() in blob:
            score += 1.2
    for proto in facets.get("protocols") or ([facets.get("protocol")] if facets.get("protocol") else []):
        if str(proto).lower() in blob:
            score += 1.0
    at = facets.get("attack_type") or ""
    if at and at.lower() in blob:
        score += 1.1
    primary = str(facets.get("primary_fs_doc") or "").lower()
    if primary and primary in blob:
        score += 12.0
    for i, fs_doc in enumerate(facets.get("preferred_fs_docs") or []):
        tag = str(fs_doc).lower()
        if tag in blob:
            if tag == "fs.21" and primary:
                score += 1.5  # weak umbrella secondary
            else:
                score += 8.0 - (i * 1.5)
    for fs_doc in facets.get("demoted_fs_docs") or []:
        tag = str(fs_doc).lower()
        if tag in blob:
            score -= 14.0 if (tag == "fs.21" and primary) else 10.0
    return score
