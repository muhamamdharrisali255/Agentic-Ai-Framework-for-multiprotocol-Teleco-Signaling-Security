"""Parse Docling output into canonical form and TOC-aware RAG chunks.

Hierarchy is driven by normalized ``toc_path`` tuples (not title+level maps),
so duplicate headings under different parents stay independent.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

import config
from docling_pipeline.entity_extractor import extract_entities
from docling_pipeline.table_serializer import (
    serialize_table_markdown,
    serialize_table_row,
    split_rows_by_budget,
)
from shared.ids import chunk_id, doc_id, row_id, section_id, table_id
from shared.schema import (
    CanonicalDocument,
    ChunkRecord,
    ContentType,
    SectionRecord,
    TableStructured,
)

# Abbreviations / dotted tokens that must not end a sentence split.
_PROTECTED_DOT = re.compile(
    r"(?i)\b(?:"
    r"e\.g|i\.e|etc|vs|mr|mrs|ms|dr|prof|fig|figs|sec|no|nos|"
    r"vol|pp|cf|approx|dept|univ|inc|ltd|co|corp|rfc|"
    r"v\d+|ver|version"
    r")\.$"
)
_IP_OR_VERSION = re.compile(
    r"(?:\d+\.){1,3}\d+$|"  # 1.2 / 192.168.1.10 trailing
    r"[A-Za-z0-9_-]+\.[A-Za-z]{2,}$"  # example.com
)


def _normalize_toc_path(value: Any) -> tuple[str, ...]:
    """Deterministic TOC path: strip empties, preserve order."""
    if value is None:
        return ()
    if isinstance(value, str):
        parts = [value]
    elif isinstance(value, (list, tuple)):
        parts = list(value)
    else:
        parts = [str(value)]
    out: list[str] = []
    for p in parts:
        s = str(p or "").strip()
        if s:
            out.append(s)
    return tuple(out)


def _table_from_data(
    data: dict[str, Any],
    document_id: str,
    section_id_val: str,
    page: Optional[int],
) -> TableStructured:
    headers = data.get("headers", [])
    raw_rows = data.get("rows", [])
    rows: List[dict[str, str]] = []
    for raw in raw_rows:
        if isinstance(raw, dict):
            rows.append({str(k): str(v) for k, v in raw.items()})
        elif isinstance(raw, (list, tuple)):
            row_dict = {}
            for i, h in enumerate(headers):
                if i < len(raw):
                    row_dict[str(h)] = str(raw[i])
            rows.append(row_dict)
    return TableStructured(
        table_id=table_id(),
        headers=[str(h) for h in headers],
        rows=rows,
        caption=data.get("caption", data.get("title", "")),
        page_number=page or data.get("page"),
        section_id=section_id_val,
        document_id=document_id,
    )


def build_canonical_from_docling_export(
    export: dict[str, Any],
    file_name: str,
) -> CanonicalDocument:
    document_id = doc_id(file_name)
    title = export.get("title", file_name)
    sections: List[SectionRecord] = []
    # Primary hierarchy key: full normalized toc_path → section_id
    id_by_path: dict[tuple[str, ...], str] = {}

    for sec_data in export.get("sections", []):
        sid = section_id()
        level = int(sec_data.get("level") or 1)
        title_s = str(sec_data.get("title") or "Untitled Section").strip()
        raw_path = sec_data.get("toc_path") or [title_s]
        path_key = _normalize_toc_path(raw_path)
        if not path_key:
            path_key = (title_s,)

        parent_id: Optional[str] = None
        parent_path = path_key[:-1]
        if parent_path:
            parent_id = id_by_path.get(parent_path)
        # Fallback (isolated): parent_title walk — only when path parent missing.
        if parent_id is None:
            parent_title = sec_data.get("parent_title")
            if parent_title:
                # Prefer longest matching path ending with parent_title.
                pt = str(parent_title).strip()
                candidates = [
                    (path, pid)
                    for path, pid in id_by_path.items()
                    if path and path[-1] == pt and len(path) < len(path_key)
                ]
                if candidates:
                    candidates.sort(key=lambda x: len(x[0]), reverse=True)
                    parent_id = candidates[0][1]

        sec = SectionRecord(
            section_id=sid,
            title=title_s,
            page_start=sec_data.get("page_start"),
            page_end=sec_data.get("page_end"),
            content=list(sec_data.get("paragraphs", [])),
            level=level,
            parent_section_id=parent_id,
            toc_path=list(path_key),
        )
        # Duplicate headings under different parents keep distinct path keys.
        id_by_path[path_key] = sid
        for tbl in sec_data.get("tables", []):
            sec.tables.append(
                _table_from_data(tbl, document_id, sec.section_id, sec.page_start)
            )
        sections.append(sec)

    return CanonicalDocument(
        document_id=document_id,
        title=title,
        file_name=file_name,
        pipeline="docling",
        sections=sections,
        metadata=export.get("metadata", {}),
    )


def _breadcrumb(doc: CanonicalDocument, section: SectionRecord) -> str:
    parts = list(_normalize_toc_path(section.toc_path or [section.title]))
    if not parts or parts[0] != doc.title:
        parts = [doc.title] + [p for p in parts if p != doc.title]
    return " > ".join(p for p in parts if p)


def _prefix(doc: CanonicalDocument, section: SectionRecord, extra: str = "") -> str:
    """Embed lead-in with full hierarchy — page/file live in Qdrant metadata."""
    lines = [
        f"Document: {doc.title}",
        f"Section: {_breadcrumb(doc, section)}",
    ]
    if extra:
        lines.append(extra)
    return "\n".join(lines)


def _make_overlap(text: str, overlap: int) -> str:
    """Suffix of ``text`` up to ``overlap`` chars, snapped to a word boundary."""
    if overlap <= 0 or not text:
        return ""
    if len(text) <= overlap:
        return text.strip()
    tail = text[-overlap:]
    space_idx = tail.find(" ")
    if space_idx >= 0 and space_idx + 1 < len(tail):
        tail = tail[space_idx + 1 :]
    return tail.strip()


def _is_protected_sentence_end(token: str, next_char: str = "") -> bool:
    t = token.rstrip()
    if not t.endswith("."):
        return False
    # Decimal / version continuation: digit after the period.
    if next_char.isdigit():
        return True
    if _PROTECTED_DOT.search(t):
        return True
    body = t[:-1]
    if _IP_OR_VERSION.search(body):
        return True
    # Single capital letter abbreviation: "A."
    if re.fullmatch(r"[A-Za-z]", body):
        return True
    return False


def _split_sentences(text: str) -> List[str]:
    """Lightweight sentence split that protects v1.0 / IPs / e.g. / domains."""
    text = text.strip()
    if not text:
        return []
    parts: List[str] = []
    buf: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        buf.append(ch)
        if ch in ".!?;:\n":
            token = "".join(buf).rstrip()
            last_ws = max(token.rfind(" "), token.rfind("\t"), token.rfind("\n"))
            last_tok = token[last_ws + 1 :] if last_ws >= 0 else token
            nxt = text[i + 1] if i + 1 < n else ""
            if ch == "." and _is_protected_sentence_end(last_tok, nxt):
                i += 1
                continue
            if ch == "\n" or nxt == "" or nxt.isspace():
                piece = "".join(buf).strip()
                if piece:
                    parts.append(piece)
                buf = []
                while i + 1 < n and text[i + 1].isspace() and text[i + 1] != "\n":
                    i += 1
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts or [text]


def _split_at_words(text: str, max_chars: int) -> List[str]:
    words = text.split()
    if not words:
        return []
    out: List[str] = []
    sub = ""
    for w in words:
        if sub and len(sub) + 1 + len(w) > max_chars:
            out.append(sub)
            sub = w
        else:
            sub = f"{sub} {w}".strip() if sub else w
    if sub:
        out.append(sub)
    return out


def _split_text(text: str, max_chars: int, overlap: int) -> List[str]:
    """Split at sentence/word boundaries — never mid-word."""
    text = text.strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]

    sentences = _split_sentences(text)
    pieces: List[str] = []
    buf = ""
    for sent in sentences:
        if buf and len(buf) + 1 + len(sent) > max_chars:
            pieces.append(buf.strip())
            tail = _make_overlap(buf, overlap)
            buf = f"{tail} {sent}".strip() if tail else sent
            # Guard against pathological growth if sentence alone is huge.
            if len(buf) > max_chars * 2:
                pieces.extend(_split_at_words(buf, max_chars))
                buf = ""
        else:
            buf = f"{buf} {sent}".strip() if buf else sent
    if buf.strip():
        pieces.append(buf.strip())

    final: List[str] = []
    for piece in pieces:
        if len(piece) <= max_chars:
            if piece.strip():
                final.append(piece.strip())
        else:
            final.extend(p for p in _split_at_words(piece, max_chars) if p.strip())
    return final or [text[:max_chars]]


def _link_sequence(chunks: List[ChunkRecord]) -> None:
    """Wire prev/next from generation order; no self-refs."""
    ids = {c.chunk_id for c in chunks}
    for i, chunk in enumerate(chunks):
        if i > 0:
            prev = chunks[i - 1].chunk_id
            chunk.prev_chunk_id = prev if prev in ids and prev != chunk.chunk_id else None
        else:
            chunk.prev_chunk_id = None
        if i + 1 < len(chunks):
            nxt = chunks[i + 1].chunk_id
            chunk.next_chunk_id = nxt if nxt in ids and nxt != chunk.chunk_id else None
        else:
            chunk.next_chunk_id = None


def canonical_to_chunks(doc: CanonicalDocument) -> List[ChunkRecord]:
    """Hierarchical, TOC-aware chunks. Nothing is embedded without its path."""
    from docling_pipeline.validate import validate_chunks, validate_sections

    validate_sections(doc)

    chunks: List[ChunkRecord] = []
    max_chars = config.DOCLING_MAX_CHUNK_CHARS
    TABLE_PART_CHARS = max_chars * 10
    overlap = config.ORIGINAL_CHUNK_OVERLAP

    toc_lines = [
        f"Document: {doc.title}",
        "Table of Contents:",
    ]
    for section in doc.sections:
        indent = "  " * max(section.level - 1, 0)
        pages = ""
        if section.page_start:
            pages = f" (page {section.page_start})"
        toc_lines.append(f"{indent}- {section.title}{pages}")
        for table in section.tables:
            cols = ", ".join(table.headers) if table.headers else ""
            toc_lines.append(
                f"{indent}  - Table: {table.caption or table.table_id}"
                + (f" | columns: {cols}" if cols else "")
            )

    toc_chunk = ChunkRecord(
        chunk_id=chunk_id(),
        document_id=doc.document_id,
        pipeline="docling",
        content="\n".join(toc_lines),
        content_type=ContentType.TOC,
        page=doc.sections[0].page_start if doc.sections else None,
        section="Table of Contents",
        toc_path=doc.title,
        file_name=doc.file_name,
        source_location="toc",
    )
    chunks.append(toc_chunk)

    heading_chunk_ids: dict[str, str] = {}

    for section in doc.sections:
        heading_id = chunk_id()
        heading_chunk_ids[section.section_id] = heading_id
        parent_heading = (
            heading_chunk_ids.get(section.parent_section_id)
            if section.parent_section_id
            else toc_chunk.chunk_id
        )
        path_parts = _normalize_toc_path(section.toc_path)
        subsection = " > ".join(path_parts[1:]) if len(path_parts) > 1 else ""
        preview = " ".join(section.content)[:400]
        heading_body = _prefix(doc, section)
        if preview:
            heading_body += f"\n\nSection summary: {preview}"
        if section.tables:
            heading_body += "\nTables in this section: " + ", ".join(
                t.caption or t.table_id for t in section.tables
            )
        crumb = _breadcrumb(doc, section)
        chunks.append(
            ChunkRecord(
                chunk_id=heading_id,
                document_id=doc.document_id,
                pipeline="docling",
                content=heading_body,
                content_type=ContentType.HEADING,
                page=section.page_start,
                section=section.title,
                subsection=subsection,
                parent_id=parent_heading,
                toc_path=crumb,
                file_name=doc.file_name,
                source_location=f"section:{section.section_id}",
            )
        )

        for para in section.content:
            for piece in _split_text(para, max_chars, overlap):
                entities = extract_entities(
                    piece, doc.document_id, section.section_id, page=section.page_start
                )
                chunks.append(
                    ChunkRecord(
                        chunk_id=chunk_id(),
                        document_id=doc.document_id,
                        pipeline="docling",
                        content=f"{_prefix(doc, section)}\n\n{piece}",
                        content_type=ContentType.LIST_ITEM
                        if piece.startswith("- ")
                        else ContentType.PARAGRAPH,
                        page=section.page_start,
                        section=section.title,
                        subsection=subsection,
                        parent_id=heading_id,
                        toc_path=crumb,
                        file_name=doc.file_name,
                        source_location=f"section:{section.section_id}",
                        entities=entities,
                    )
                )

        for table in section.tables:
            parts = split_rows_by_budget(table, TABLE_PART_CHARS)
            table_chunk_id = ""
            for part_index, part_rows in enumerate(parts):
                part_id = chunk_id()
                if not table_chunk_id:
                    table_chunk_id = part_id
                label = f"Table: {table.caption or table.table_id}"
                if len(parts) > 1:
                    label += f" (part {part_index + 1} of {len(parts)})"
                md = serialize_table_markdown(table, max_rows=None, rows=part_rows)
                chunks.append(
                    ChunkRecord(
                        chunk_id=part_id,
                        document_id=doc.document_id,
                        pipeline="docling",
                        content=f"{_prefix(doc, section, extra=label)}\n\n{md}",
                        content_type=ContentType.TABLE,
                        page=table.page_number,
                        section=section.title,
                        subsection=subsection,
                        table_id=table.table_id,
                        parent_id=heading_id if part_index == 0 else table_chunk_id,
                        toc_path=crumb,
                        file_name=doc.file_name,
                        source_location=f"table:{table.table_id},part:{part_index}",
                        structured_table=table,
                    )
                )
            for i, row in enumerate(table.rows):
                rid = row_id()
                row_text = serialize_table_row(
                    table, row, doc.title, crumb, i
                )
                row_entities = extract_entities(
                    row_text,
                    doc.document_id,
                    section.section_id,
                    table.table_id,
                    rid,
                    table.page_number,
                )
                chunks.append(
                    ChunkRecord(
                        chunk_id=chunk_id(),
                        document_id=doc.document_id,
                        pipeline="docling",
                        content=row_text,
                        content_type=ContentType.TABLE_ROW,
                        page=table.page_number,
                        section=section.title,
                        subsection=subsection,
                        table_id=table.table_id,
                        row_id=rid,
                        parent_id=table_chunk_id,
                        toc_path=crumb,
                        file_name=doc.file_name,
                        source_location=f"table:{table.table_id},row:{i}",
                        entities=row_entities,
                        structured_table=table,
                    )
                )

    _link_sequence(chunks)
    validate_chunks(chunks)
    return chunks
