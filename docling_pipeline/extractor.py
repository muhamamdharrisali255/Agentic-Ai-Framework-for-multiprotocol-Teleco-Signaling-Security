"""Docling document extraction — preserves TOC, tables, and reading order."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, List, Optional

from shared.ids import reset_ids

_HEADING_LABELS = {"title", "heading", "section_header", "section", "subtitle"}
_SKIP_LABELS = {"page_header", "page_footer", "footnote"}


def _page_number(prov: Any) -> Optional[int]:
    if prov is None:
        return None
    if hasattr(prov, "page_no"):
        return int(prov.page_no)
    if isinstance(prov, dict):
        return prov.get("page_no") or prov.get("page")
    return None


def _item_page(item: Any, fallback: Optional[int]) -> Optional[int]:
    prov = getattr(item, "prov", None)
    if prov and hasattr(prov, "__iter__") and not isinstance(prov, (str, dict)):
        prov_list = list(prov)
        return _page_number(prov_list[0]) if prov_list else fallback
    return _page_number(prov) or fallback


def _iter_items(doc: Any) -> List[Any]:
    if hasattr(doc, "iterate_items"):
        return list(doc.iterate_items())
    return []


def _text_of(item: Any) -> str:
    if hasattr(item, "text"):
        return str(item.text or "").strip()
    if isinstance(item, dict):
        return str(item.get("text", "")).strip()
    return str(item).strip()


def _label_of(item: Any) -> str:
    if hasattr(item, "label"):
        return str(item.label).lower()
    return ""


def _new_section(
    title: str,
    page: Optional[int],
    level: int,
    parent_title: str,
    toc_path: List[str],
) -> dict[str, Any]:
    return {
        "title": title,
        "page_start": page,
        "page_end": page,
        "level": level,
        "parent_title": parent_title,
        "toc_path": toc_path,
        "paragraphs": [],
        "tables": [],
    }


def extract_with_docling(path: Path) -> dict[str, Any]:
    """Extract structured document using Docling, keeping TOC and mid-document text."""
    from shared.docling_gpu import get_docling_converter
    from shared.ids import reset_ids

    reset_ids()
    converter = get_docling_converter()
    result = converter.convert(str(path))
    dl_doc = result.document

    title = path.stem.replace("_", " ").replace("-", " ").title()
    if hasattr(dl_doc, "name") and dl_doc.name:
        title = str(dl_doc.name)

    sections: List[dict[str, Any]] = []
    current_section: Optional[dict[str, Any]] = None
    current_page: Optional[int] = None
    heading_stack: List[tuple[int, dict[str, Any]]] = []

    def _ensure_section(heading: str = "Main Content") -> dict[str, Any]:
        nonlocal current_section
        if current_section is None:
            current_section = _new_section(heading, current_page, 1, title, [title, heading])
            sections.append(current_section)
            heading_stack.append((1, current_section))
        return current_section

    items = _iter_items(dl_doc)
    if not items and hasattr(dl_doc, "export_to_markdown"):
        return _markdown_fallback_export(path, dl_doc.export_to_markdown(), title)

    for item, level in items:
        label = _label_of(item)
        if label in _SKIP_LABELS:
            continue
        text = _text_of(item)
        page = _item_page(item, current_page)
        if page:
            current_page = page
        heading_level = int(level) if isinstance(level, int) else 1

        is_heading = label in _HEADING_LABELS or "heading" in label
        if is_heading and text:
            while heading_stack and heading_stack[-1][0] >= heading_level:
                heading_stack.pop()
            parent = heading_stack[-1][1] if heading_stack else None
            parent_title = parent["title"] if parent else title
            toc_path = ([title] + [s["title"] for _, s in heading_stack] + [text])
            current_section = _new_section(text, page, heading_level, parent_title, toc_path)
            sections.append(current_section)
            heading_stack.append((heading_level, current_section))
            continue

        if "table" in label:
            sec = _ensure_section()
            tbl = _extract_table(item, page, dl_doc)
            if tbl:
                if not tbl.get("caption"):
                    tbl["caption"] = sec.get("title") or ""
                sec["tables"].append(tbl)
            continue

        if text:
            sec = _ensure_section()
            if "list" in label:
                sec["paragraphs"].append(f"- {text}")
            elif "caption" in label:
                sec["paragraphs"].append(f"Caption: {text}")
            else:
                sec["paragraphs"].append(text)
            if page:
                sec["page_end"] = page

    if not sections:
        md = dl_doc.export_to_markdown() if hasattr(dl_doc, "export_to_markdown") else ""
        return _markdown_fallback_export(path, md, title)

    _merge_document_tables(sections, dl_doc)
    if hasattr(dl_doc, "export_to_markdown"):
        md = dl_doc.export_to_markdown()
        # The markdown export renders the same tables with flattened headers, so it
        # only helps when the structured paths found nothing; merging it otherwise
        # stores a second, lower-fidelity copy of every table.
        if not any(sec.get("tables") for sec in sections):
            _merge_markdown_tables(sections, md)
        _fill_missing_paragraphs(sections, md, title)

    return {
        "title": title,
        "sections": sections,
        "metadata": {"source": str(path), "extractor": "docling"},
        "toc": [
            {
                "title": s["title"],
                "level": s.get("level", 1),
                "page_start": s.get("page_start"),
                "page_end": s.get("page_end"),
                "toc_path": s.get("toc_path") or [s["title"]],
                "table_count": len(s.get("tables") or []),
            }
            for s in sections
        ],
    }


def _table_key(tbl: dict[str, Any]) -> tuple:
    headers = tuple(str(h).lower() for h in (tbl.get("headers") or []))
    first = tuple(str(v) for v in ((tbl.get("rows") or [{}])[0].values())) if tbl.get("rows") else ()
    return (headers, first)


def _attach_table(sections: List[dict[str, Any]], tbl: dict[str, Any]) -> None:
    caption = (tbl.get("caption") or "").strip().lower()
    if caption:
        for sec in sections:
            title = (sec.get("title") or "").strip().lower()
            if title and (title == caption or caption in title or title in caption):
                sec.setdefault("tables", []).append(tbl)
                return
    for sec in reversed(sections):
        title = (sec.get("title") or "").lower()
        if not sec.get("tables") and title and any(
            k in title for k in ("inventory", "table", "servers", "virtual machines")
        ):
            if not tbl.get("caption"):
                tbl["caption"] = sec.get("title")
            sec.setdefault("tables", []).append(tbl)
            return
    if sections:
        sections[-1].setdefault("tables", []).append(tbl)
    else:
        sections.append(_new_section(tbl.get("caption") or "Tables", tbl.get("page"), 1, "", []))
        sections[-1]["tables"].append(tbl)


def _merge_document_tables(sections: List[dict[str, Any]], dl_doc: Any) -> None:
    existing = {_table_key(t) for sec in sections for t in sec.get("tables", [])}
    for item in getattr(dl_doc, "tables", []) or []:
        page = _item_page(item, None)
        tbl = _extract_table(item, page, dl_doc)
        if not tbl or _table_key(tbl) in existing:
            continue
        existing.add(_table_key(tbl))
        _attach_table(sections, tbl)


def _merge_markdown_tables(sections: List[dict[str, Any]], md: str) -> None:
    parsed = _markdown_fallback_export(Path("."), md, "tmp")
    existing = {_table_key(t) for sec in sections for t in sec.get("tables", [])}
    by_title = {(s.get("title") or "").strip().lower(): s for s in sections}
    for sec in parsed.get("sections", []):
        for tbl in sec.get("tables", []):
            if not tbl.get("rows") or _table_key(tbl) in existing:
                continue
            if not tbl.get("caption"):
                tbl["caption"] = sec.get("title") or ""
            existing.add(_table_key(tbl))
            target = by_title.get((sec.get("title") or "").strip().lower())
            if target is not None:
                target.setdefault("tables", []).append(tbl)
            else:
                _attach_table(sections, tbl)


def _normalize_para(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _fill_missing_paragraphs(sections: List[dict[str, Any]], md: str, doc_title: str) -> None:
    """Pull any markdown paragraphs Docling reading-order missed."""
    parsed = _markdown_fallback_export(Path("."), md, doc_title)
    known = {_normalize_para(p) for sec in sections for p in sec.get("paragraphs", [])}
    by_title = {(s.get("title") or "").strip().lower(): s for s in sections}
    for sec in parsed.get("sections", []):
        target = by_title.get((sec.get("title") or "").strip().lower())
        if target is None:
            continue
        for para in sec.get("paragraphs", []):
            if para.startswith("|"):
                continue
            key = _normalize_para(para)
            if key and key not in known:
                target["paragraphs"].append(para)
                known.add(key)


def _unique_headers(raw: list[Any]) -> list[str]:
    """Distinct column names.

    Merged header cells give several columns the same label; without unique
    keys a row dict collapses columns and pandas lookups return a Series whose
    repr ("Name: 1, dtype: str") would be stored as the cell value.
    """
    seen: dict[str, int] = {}
    headers: list[str] = []
    for i, cell in enumerate(raw):
        name = str(cell).strip() or f"Column {i + 1}"
        seen[name] = seen.get(name, 0) + 1
        headers.append(name if seen[name] == 1 else f"{name} ({seen[name]})")
    return headers


def _row_dict(headers: list[str], values: list[Any]) -> dict[str, str]:
    """Map cells to headers by position, so no column is lost or duplicated."""
    return {
        h: ("" if i >= len(values) or values[i] is None else str(values[i]).strip())
        for i, h in enumerate(headers)
    }


def _extract_table(item: Any, page: Optional[int], dl_doc: Any = None) -> Optional[dict[str, Any]]:
    caption = ""
    if hasattr(item, "caption") and item.caption:
        caption = str(item.caption)
    if hasattr(item, "export_to_dataframe"):
        try:
            df = item.export_to_dataframe(doc=dl_doc) if dl_doc is not None else item.export_to_dataframe()
            raw_headers = df.columns.tolist()
            if raw_headers and all(str(h).isdigit() for h in raw_headers) and len(df) > 0:
                raw_headers = df.iloc[0].tolist()
                df = df.iloc[1:].copy()
            headers = _unique_headers(raw_headers)
            rows = [_row_dict(headers, df.iloc[i].tolist()) for i in range(len(df))]
            return {"headers": headers, "rows": rows, "page": page, "caption": caption}
        except Exception:
            pass
    data = getattr(item, "table_data", None)
    if data and hasattr(data, "grid") and data.grid:
        grid = data.grid
        headers = _unique_headers(list(grid[0]))
        rows = [_row_dict(headers, list(row_cells)) for row_cells in grid[1:]]
        return {"headers": headers, "rows": rows, "page": page, "caption": caption}
    return None


def _markdown_fallback_export(path: Path, md: str, title: str) -> dict[str, Any]:
    sections: List[dict[str, Any]] = []
    current: Optional[dict[str, Any]] = None
    stack: List[tuple[int, dict[str, Any]]] = []

    for line in md.splitlines():
        heading_match = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading_match:
            level = len(heading_match.group(1))
            heading = heading_match.group(2).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            parent_title = stack[-1][1]["title"] if stack else title
            toc_path = [title] + [s["title"] for _, s in stack] + [heading]
            current = _new_section(heading, None, level, parent_title, toc_path)
            sections.append(current)
            stack.append((level, current))
            continue

        if line.strip().startswith("|") and "|" in line[1:]:
            if current is None:
                current = _new_section("Main Content", None, 1, title, [title, "Main Content"])
                sections.append(current)
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= {"-", ":"} for c in cells if c):
                continue
            tables = current.setdefault("tables", [])
            if not tables or (tables[-1].get("rows") and not _is_open_markdown_table(tables[-1], cells)):
                tables.append({"headers": cells, "rows": [], "page": None, "caption": current.get("title", "")})
            elif not tables[-1].get("rows") and tables[-1].get("headers") and len(tables[-1]["headers"]) == len(cells):
                headers = tables[-1]["headers"]
                tables[-1].setdefault("rows", []).append(
                    {headers[i]: cells[i] if i < len(cells) else "" for i in range(len(headers))}
                )
            else:
                headers = tables[-1].get("headers", [])
                tables[-1].setdefault("rows", []).append(
                    {headers[i]: cells[i] if i < len(cells) else "" for i in range(len(headers))}
                )
            continue

        if line.strip() and current is not None:
            current["paragraphs"].append(line.strip())
        elif line.strip() and current is None:
            current = _new_section("Main Content", None, 1, title, [title, "Main Content"])
            current["paragraphs"].append(line.strip())
            sections.append(current)

    if not sections and md.strip():
        sections = [_new_section("Main Content", None, 1, title, [title, "Main Content"])]
        sections[0]["paragraphs"] = [md.strip()]

    return {
        "title": title,
        "sections": sections,
        "metadata": {"source": str(path), "extractor": "docling-markdown-fallback"},
        "toc": [{"title": s["title"], "level": s.get("level", 1), "toc_path": s.get("toc_path")} for s in sections],
    }


def _is_open_markdown_table(tbl: dict[str, Any], cells: list[str]) -> bool:
    headers = tbl.get("headers") or []
    return len(headers) == len(cells)


def save_canonical_json(export: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(export, indent=2), encoding="utf-8")
