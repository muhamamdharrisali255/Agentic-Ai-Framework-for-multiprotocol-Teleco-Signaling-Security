"""Stable ID generation for documents, sections, tables, rows."""

from __future__ import annotations

import hashlib
import re

_counter: dict[str, int] = {}


def reset_ids() -> None:
    _counter.clear()


def _next(prefix: str) -> str:
    _counter[prefix] = _counter.get(prefix, 0) + 1
    return f"{prefix}_{_counter[prefix]:03d}"


def doc_id(file_name: str | None = None) -> str:
    """Stable per-file document id (avoids DOC_001 collisions across documents)."""
    if file_name:
        stem = re.sub(r"[^A-Za-z0-9]+", "_", file_name.rsplit(".", 1)[0])[:40].strip("_")
        digest = hashlib.sha1(file_name.encode("utf-8")).hexdigest()[:8]
        return f"DOC_{stem}_{digest}"
    return _next("DOC")


def section_id() -> str:
    return _next("SEC")


def paragraph_id() -> str:
    return _next("PAR")


def table_id() -> str:
    return _next("TABLE")


def row_id() -> str:
    return _next("ROW")


def chunk_id() -> str:
    return _next("CHUNK")
