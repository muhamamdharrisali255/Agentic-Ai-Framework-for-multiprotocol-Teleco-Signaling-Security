"""Lightweight validation for canonical sections and RAG chunks."""

from __future__ import annotations

import logging
from typing import Iterable

from shared.schema import CanonicalDocument, ChunkRecord, ContentType

logger = logging.getLogger(__name__)


class ValidationError(ValueError):
    """Raised when hierarchy or chunk integrity checks fail."""


def validate_sections(doc: CanonicalDocument) -> None:
    """Unique section IDs, normalized TOC paths, valid parents (no self-parent)."""
    ids = [s.section_id for s in doc.sections]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise ValidationError(f"Duplicate section IDs: {dupes}")

    id_set = set(ids)
    for sec in doc.sections:
        path = [str(p).strip() for p in (sec.toc_path or []) if str(p).strip()]
        if not path:
            raise ValidationError(f"Section {sec.section_id!r} has empty toc_path")
        if sec.parent_section_id:
            if sec.parent_section_id == sec.section_id:
                raise ValidationError(f"Section {sec.section_id!r} is its own parent")
            if sec.parent_section_id not in id_set:
                raise ValidationError(
                    f"Section {sec.section_id!r} parent_section_id "
                    f"{sec.parent_section_id!r} not found"
                )
    logger.info(
        "sections_validated document_id=%s sections=%s",
        doc.document_id,
        len(doc.sections),
    )


def validate_chunks(chunks: Iterable[ChunkRecord]) -> None:
    """Unique chunk IDs, document binding, parent/prev/next integrity, table links."""
    chunk_list = list(chunks)
    ids = [c.chunk_id for c in chunk_list]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise ValidationError(f"Duplicate chunk IDs: {dupes}")

    by_id = {c.chunk_id: c for c in chunk_list}
    for c in chunk_list:
        if not c.document_id:
            raise ValidationError(f"Chunk {c.chunk_id!r} missing document_id")
        if not (c.content or "").strip():
            raise ValidationError(f"Chunk {c.chunk_id!r} has empty content")
        if c.content_type != ContentType.TOC and not (c.toc_path or "").strip():
            raise ValidationError(f"Chunk {c.chunk_id!r} missing toc_path")

        if c.parent_id:
            if c.parent_id == c.chunk_id:
                raise ValidationError(f"Chunk {c.chunk_id!r} is its own parent")
            if c.parent_id not in by_id:
                raise ValidationError(
                    f"Chunk {c.chunk_id!r} parent_id {c.parent_id!r} not found"
                )

        for rel_name, rel_id in (
            ("prev_chunk_id", c.prev_chunk_id),
            ("next_chunk_id", c.next_chunk_id),
        ):
            if not rel_id:
                continue
            if rel_id == c.chunk_id:
                raise ValidationError(f"Chunk {c.chunk_id!r} self-{rel_name}")
            if rel_id not in by_id:
                raise ValidationError(
                    f"Chunk {c.chunk_id!r} {rel_name} {rel_id!r} not found"
                )

        if c.content_type == ContentType.TABLE:
            if not c.table_id:
                raise ValidationError(f"TABLE chunk {c.chunk_id!r} missing table_id")
        if c.content_type == ContentType.TABLE_ROW:
            if not c.table_id:
                raise ValidationError(f"TABLE_ROW {c.chunk_id!r} missing table_id")
            if not c.row_id:
                raise ValidationError(f"TABLE_ROW {c.chunk_id!r} missing row_id")
            if not c.parent_id or c.parent_id not in by_id:
                raise ValidationError(
                    f"TABLE_ROW {c.chunk_id!r} parent must point to TABLE chunk"
                )
            parent = by_id[c.parent_id]
            if parent.content_type != ContentType.TABLE:
                raise ValidationError(
                    f"TABLE_ROW {c.chunk_id!r} parent {c.parent_id!r} is not TABLE"
                )

    logger.info(
        "chunks_validated document_id=%s chunks=%s",
        chunk_list[0].document_id if chunk_list else "",
        len(chunk_list),
    )
