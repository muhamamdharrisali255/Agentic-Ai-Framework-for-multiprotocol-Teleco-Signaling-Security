"""Human-readable indexing reports for the UI."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from shared.schema import ChunkRecord, ContentType


def _section_rows(chunks: Iterable[ChunkRecord]) -> list[dict]:
    by_section: dict[str, dict] = {}
    order: list[str] = []

    for chunk in chunks:
        if chunk.content_type == ContentType.TOC:
            continue
        key = chunk.section or "Main Content"
        if key not in by_section:
            by_section[key] = {
                "title": key,
                "toc_path": chunk.toc_path or key,
                "page": chunk.page,
                "counts": Counter(),
            }
            order.append(key)
        row = by_section[key]
        row["counts"][chunk.content_type.value] += 1
        if chunk.toc_path and len(chunk.toc_path) >= len(row["toc_path"]):
            row["toc_path"] = chunk.toc_path
        if chunk.page and (row["page"] is None or chunk.page < row["page"]):
            row["page"] = chunk.page

    return [by_section[k] for k in order]


def build_index_report(chunks: list[ChunkRecord], pipeline: str, file_name: str) -> str:
    """Markdown summary showing TOC-aware, section-by-section indexing."""
    if not chunks:
        return "_No chunks produced._"

    type_counts = Counter(c.content_type.value for c in chunks)
    lines = [
        f"### {pipeline.upper()} index report — `{file_name}`",
        f"- **Total chunks:** {len(chunks)}",
        f"- **Chunk types:** "
        + ", ".join(f"`{k}`={v}" for k, v in sorted(type_counts.items())),
    ]

    if pipeline == "docling":
        toc_chunks = [c for c in chunks if c.content_type == ContentType.TOC]
        if toc_chunks:
            preview = toc_chunks[0].content.strip().splitlines()[:18]
            lines.extend(["", "**Table of Contents chunk** (embedded for navigation):"])
            lines.append("```")
            lines.extend(preview)
            if len(toc_chunks[0].content.splitlines()) > 18:
                lines.append("...")
            lines.append("```")

        lines.extend(
            [
                "",
                "**Section-by-section breakdown** (each section gets a heading chunk, "
                "then paragraph/table chunks with `Table of Contents path` metadata):",
                "",
                "| Section | Page | Chunks | Types |",
                "| --- | ---: | ---: | --- |",
            ]
        )
        for row in _section_rows(chunks):
            counts = row["counts"]
            total = sum(counts.values())
            type_bits = ", ".join(f"{k}×{v}" for k, v in sorted(counts.items()))
            page = row["page"] if row["page"] is not None else "—"
            title = row["title"].replace("|", "\\|")
            lines.append(f"| {title} | {page} | {total} | {type_bits} |")

        lines.extend(
            [
                "",
                "**Sample indexed chunk paths:**",
            ]
        )
        samples = [
            c
            for c in chunks
            if c.content_type in (ContentType.PARAGRAPH, ContentType.TABLE, ContentType.HEADING)
            and c.toc_path
        ][:6]
        for c in samples:
            lines.append(
                f"- `{c.content_type.value}` · section `{c.section or '—'}` · "
                f"path `{c.toc_path}` · page {c.page or '—'}"
            )
    else:
        pages = sorted({c.page for c in chunks if c.page})
        sectioned = sum(1 for c in chunks if c.section)
        lines.extend(
            [
                "",
                f"- **Pages covered:** {len(pages)}",
                f"- **Chunks with a section heading:** {sectioned}/{len(chunks)}",
                "- **Method:** section-aware text chunks (headings detected, lists kept intact)",
            ]
        )

    return "\n".join(lines)
