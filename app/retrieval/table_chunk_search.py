"""Extract structured rows from docling table chunks (domain-agnostic)."""

from __future__ import annotations

import re
from typing import Any, Optional

_NOISE_KEYS = frozenset({
    "document", "section", "table", "page", "pages", "table of contents path",
    "table of contents", "columns", "name", "dtype",
})
_NAME_BLOCK_RE = re.compile(r"Name:\s*(\d+)\s*,\s*dtype:\s*str", re.I)
_COL_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/\s]{0,30}?\s{2,}")
_VERSION_RE = re.compile(r"\b([A-Z]{2,10}v\d+(?:\s+[A-Z]{2,10}v\d+)*)\b", re.I)


def search_docling_table_chunks(
    query: str,
    *,
    file_name: Optional[str] = None,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Retrieve docling chunks and extract key-value table rows."""
    from shared.retrieval import retrieve

    pool = max(limit * 3, 18)
    hits = retrieve(query, "docling", top_k=pool, document=file_name)

    if len(hits) < 4:
        tokens = " ".join(t for t in re.split(r"\W+", query) if len(t) >= 4)
        if tokens:
            extra_hits = retrieve(f"{query} {tokens}", "docling", top_k=pool, document=file_name)
            seen_ids = {h.chunk.chunk_id for h in hits}
            for h in extra_hits:
                if h.chunk.chunk_id not in seen_ids:
                    hits.append(h)

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    for h in hits:
        ch = h.chunk
        text = ch.content or ""
        if not text.strip():
            continue
        section = ch.section or ""
        page = ch.page
        fn = ch.file_name or file_name or ""

        for item in extract_rows_from_chunk(text, section=section, page=page, file_name=fn):
            key = f"{item.get('Field')}|{item.get('Value')}|{item.get('_page')}"
            if key in seen:
                continue
            seen.add(key)
            rows.append(item)
            if len(rows) >= limit * 2:
                break

    return _rank_rows(rows, query)[:limit]


def extract_rows_from_chunk(
    text: str,
    *,
    section: str,
    page: int | None,
    file_name: str,
) -> list[dict[str, Any]]:
    """Generic key-value / table-row extraction from a docling chunk."""
    out: list[dict[str, Any]] = []
    src = f"{file_name} p.{page}" if page else file_name

    out.extend(_extract_name_blocks(text, section, src, page, file_name))
    out.extend(_extract_colon_pairs(text, section, src, page, file_name))
    out.extend(_extract_markdown_pairs(text, section, src, page, file_name))

    return _dedupe_rows(out)


def _extract_name_blocks(
    text: str,
    section: str,
    src: str,
    page: int | None,
    file_name: str,
) -> list[dict[str, Any]]:
    """Parse pandas-style table cells: content ... Name: N, dtype: str."""
    if "Name:" not in text or "dtype:" not in text:
        return []

    parts = _NAME_BLOCK_RE.split(text)
    if len(parts) < 3:
        return []

    blocks: list[tuple[int, list[str]]] = []
    i = 1
    while i < len(parts):
        try:
            row_num = int(parts[i])
        except (TypeError, ValueError):
            i += 2
            continue
        body = parts[i + 1] if i + 1 < len(parts) else ""
        lines = _meaningful_lines(body)
        if lines:
            blocks.append((row_num, lines))
        i += 2

    if not blocks:
        return []

    out: list[dict[str, Any]] = []
    label_lines: list[str] = []
    for row_num, lines in sorted(blocks, key=lambda x: x[0]):
        if _looks_like_labels(lines) and not _has_version_tokens(lines):
            label_lines = lines
            continue

        if _has_version_tokens(lines) or _is_substantive_values(lines):
            values = _unique_substantive(lines)
            if label_lines:
                for idx, val in enumerate(values):
                    field = label_lines[idx] if idx < len(label_lines) else f"{section or 'Table'} row {row_num}"
                    out.append(_row(field, val, section, src, page, file_name, row_num=row_num))
                label_lines = []
            else:
                for val in values:
                    field = _infer_field_from_value(val, section, row_num)
                    out.append(_row(field, val, section, src, page, file_name, row_num=row_num))
        elif len(lines) == 1:
            val = lines[0]
            field = _infer_field_from_value(val, section, row_num)
            out.append(_row(field, val, section, src, page, file_name, row_num=row_num))

    return out


def _extract_colon_pairs(
    text: str,
    section: str,
    src: str,
    page: int | None,
    file_name: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in re.finditer(r"(?m)^([A-Za-z0-9][^:\n|]{1,40}?):\s*(.+)$", text):
        key = m.group(1).strip()
        raw_val = m.group(2).strip()
        if _is_noise(key) or key.lower().startswith("document"):
            continue
        val = _clean_cell(raw_val)
        if not val or len(val) < 2:
            continue
        if val == key or val.startswith(key):
            val = _strip_column_prefix(val)
        if not val or val == key:
            continue
        if _has_version_tokens([val]):
            field = _infer_field_from_value(val, section, None)
            out.append(_row(field, val, section, src, page, file_name))
        elif len(val) > 8 and not _looks_like_column_label(val):
            out.append(_row(_strip_column_prefix(key) or key, val, section, src, page, file_name))
    return out


def _extract_markdown_pairs(
    text: str,
    section: str,
    src: str,
    page: int | None,
    file_name: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in re.finditer(r"\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|", text):
        left, right = m.group(1).strip(), _clean_cell(m.group(2))
        if left.startswith("---") or _is_noise(left) or not right:
            continue
        left = _strip_column_prefix(left)
        right = _strip_column_prefix(right)
        if len(left) > 100 or not right or left == right:
            continue
        if _has_version_tokens([right]):
            out.append(_row(left or _infer_field_from_value(right, section, None), right, section, src, page, file_name))
        elif len(right) >= 3:
            out.append(_row(left, right, section, src, page, file_name))
    return out


def _meaningful_lines(block: str) -> list[str]:
    lines: list[str] = []
    for raw in block.split("\n"):
        line = raw.strip()
        if not line or line.startswith("|") or line.startswith("---"):
            continue
        if "dtype:" in line.lower():
            continue
        if ":" in line:
            label, _, rest = line.partition(":")
            # Only treat it as "Label: value" when a real label precedes it.
            if rest.strip() and len(label.strip()) <= 60:
                line = rest.strip()
        line = _strip_column_prefix(line)
        line = _clean_cell(line)
        if line and line not in lines:
            lines.append(line)
    return lines


def _looks_like_column_label(value: str) -> bool:
    """A single digit-free short token is a header, not a documented value."""
    v = (value or "").strip()
    return bool(v) and len(v.split()) == 1 and len(v) < 12 and not any(c.isdigit() for c in v)


def _strip_column_prefix(text: str) -> str:
    s = (text or "").strip()
    # Pandas tables often pad with 2+ spaces: "gsmSSF/MSC     CAP Version..."
    s = re.sub(r"^[A-Za-z0-9][A-Za-z0-9/\s]{0,30}?\s{2,}", "", s)
    # Single-space repeated column header: "gsmSSF/MSC CAPv1..." -> "CAPv1..."
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9/]*)\s+(.+)$", s)
    if m and "/" in m.group(1) and not m.group(2).lower().startswith(m.group(1).lower()):
        s = m.group(2).strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9/]*):\s*(.+)$", s)
    if m and len(m.group(2)) >= 3:
        s = m.group(2).strip()
    return s.strip()


def _looks_like_labels(lines: list[str]) -> bool:
    return any(
        len(l) > 12 and re.search(r"[A-Za-z]{4,}", l) and not _has_version_tokens([l])
        for l in lines
    )


def _has_version_tokens(lines: list[str]) -> bool:
    return any(_VERSION_RE.search(l) for l in lines)


def _is_substantive_values(lines: list[str]) -> bool:
    vals = _unique_substantive(lines)
    return len(vals) > 0 and all(len(v) >= 2 for v in vals)


def _unique_substantive(lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        val = line.strip()
        if not val or val.lower() in ("yes / no", "planned date"):
            continue
        if val in out:
            continue
        out.append(val)
    return out


def _infer_field_from_value(value: str, section: str, row_num: int | None) -> str:
    if row_num is not None:
        return f"{section or 'Table'} row {row_num}"
    return section or "Table"


def _row(
    field: str,
    value: str,
    section: str,
    source: str,
    page: int | None,
    file_name: str,
    *,
    row_num: int | None = None,
) -> dict[str, Any]:
    field = field.strip()[:120]
    value = _strip_column_prefix(_clean_cell(value))
    row = {
        "Field": field,
        "Value": value[:200],
        "Section": section,
        "Source": source,
        "_page": page,
        "_document_id": file_name,
    }
    if row_num is not None:
        row["Row"] = row_num
    return row


def _clean_cell(text: str) -> str:
    s = re.sub(r"\s+", " ", (text or "").strip())
    s = re.sub(r"\s*Name:\s*\d+\s*,?\s*dtype:\s*str\s*$", "", s, flags=re.I)
    return s.strip()[:200]


def _is_noise(key: str) -> bool:
    k = key.lower().strip()
    if k in _NOISE_KEYS:
        return True
    return k.startswith("table of contents")


def _normalize_value(value: str) -> str:
    v = _strip_column_prefix(_clean_cell(value))
    return re.sub(r"\s+", " ", v.lower())


def _dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        field = str(row.get("Field", "")).strip()
        value = str(row.get("Value", "")).strip()
        if not value or field == value:
            continue
        if value.lower() in ("yes / no", "n/a", "section id", "description"):
            continue
        if len(value) < 5 and not _has_version_tokens([value]):
            continue
        # A one-word, digit-free short cell is almost always a column header
        # bleeding in as a value (e.g. an equipment or column label).
        if len(value.split()) == 1 and len(value) < 12 and not any(c.isdigit() for c in value):
            continue
        if field.upper() == field and len(field) < 12 and not _has_version_tokens([value]):
            # Skip bare section headers reused as field names
            if "version" not in value.lower():
                continue
        if len(field) <= 2:
            continue
        if _looks_like_labels([value]) and not _has_version_tokens([value]):
            continue
        norm_val = _normalize_value(value)
        if not norm_val:
            continue
        score = len(field)
        if "supported" in field.lower() or "version" in field.lower():
            score += 20
        if row.get("Row") is not None and "row" not in field.lower():
            score += 3
        prev = best.get(norm_val)
        if prev is None or score > prev.get("_score", 0):
            row = dict(row)
            row["Value"] = _strip_column_prefix(value)
            row["_score"] = score
            best[norm_val] = row
    out = list(best.values())
    for r in out:
        r.pop("_score", None)
    return out


def _rank_rows(rows: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    tokens = {t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 3}

    def score(row: dict[str, Any]) -> float:
        blob = f"{row.get('Field','')} {row.get('Value','')} {row.get('Section','')}".lower()
        s = sum(1 for t in tokens if t in blob)
        if _has_version_tokens([str(row.get("Value", ""))]):
            s += 2.0
        if row.get("Row") is not None:
            s += 0.5
        if len(str(row.get("Value", ""))) < 4:
            s -= 2.0
        return s

    rows.sort(key=score, reverse=True)
    return rows


def build_lookup_answer(query: str, context: str) -> str | None:
    """Professional lookup brief built from evidence rows (LLM-independent)."""
    if not (query and context):
        return None

    rows: list[dict[str, Any]] = []
    for block in re.split(r"SOURCE \d+:", context):
        source = ""
        m = re.search(r"Source:\s*(.+?)(?:\n|$)", block)
        if m:
            source = m.group(1).strip()
        ev_m = re.search(r"Evidence:\s*\n(.*)", block, re.S)
        if not ev_m:
            continue
        body = ev_m.group(1).strip()
        section = _section_from_body(body)
        fn = source.split(" p.")[0] if source else ""
        page = _page_from_source(source)
        for row in extract_rows_from_chunk(body, section=section, page=page, file_name=fn):
            item = dict(row)
            item["Source"] = source or item.get("Source", "")
            rows.append(item)

    if not rows:
        return None

    terms = _query_terms(query)
    ranked = [r for r in _rank_rows(rows, query) if _row_answer_score(r, query) >= 1.0]
    # A brief is only trustworthy when rows actually address the question.
    ranked = [r for r in ranked if _row_matches_terms(r, terms)]
    if not ranked:
        return None

    cleaned: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for row in ranked[:10]:
        field = re.sub(r"^[\s\-–—*•|:]+", "", str(row.get("Field", ""))).strip()
        value = str(row.get("Value", "")).strip()
        src = str(row.get("Source", "")).strip()
        section = str(row.get("Section", "")).strip()
        if not field or not value or field == value:
            continue
        # Never surface internal index metadata or bare citation labels as answers.
        if field.lower() in {
            "chunk_id",
            "document_id",
            "point_key",
            "embedding_model",
            "vector_backend",
            "reference",
            "ref",
        }:
            # Allow Reference rows only when the query is explicitly about a reference/TS.
            if field.lower() in {"reference", "ref"}:
                if not re.search(
                    r"\breference\b|\b3gpp\s*ts\b|\bts\s*29\b|\bcite\b",
                    (query or "").lower(),
                ):
                    continue
            else:
                continue
        if "|" in value:
            value = re.sub(r"\s*\|\s*", " ", value).strip()
        # A row whose field just repeats its section carries no label; try to
        # recover "Label: value" from the cell, else drop it.
        if section and field.upper() == section.upper():
            label, _, rest = value.partition(":")
            if rest.strip() and len(label.strip()) <= 60:
                field, value = label.strip(), rest.strip()
            else:
                continue
        key = f"{field.lower()}|{value.lower()}"
        if key in seen:
            continue
        seen.add(key)
        cleaned.append((
            field.replace("|", "/"),
            value.replace("|", "/"),
            section or "—",
            src or "—",
        ))

    if not cleaned:
        return None

    lines = [
        "## Summary",
        "",
        _summary_from_rows(cleaned),
        "",
        "## Documented values",
        "",
        "| Field | Value | Section | Source |",
        "| :--- | :--- | :--- | :--- |",
    ]
    lines.extend(f"| {f} | {v} | {s} | {src} |" for f, v, s, src in cleaned)

    sources = _distinct_sources(cleaned)
    lines.extend(["", f"**Source:** {'; '.join(sources)}"])
    return "\n".join(lines)


def _query_terms(query: str) -> set[str]:
    stop = {
        "what", "which", "does", "do", "the", "are", "is", "and", "for", "from",
        "with", "list", "all", "show", "give", "find", "any", "that", "this",
        "document", "documents", "table", "rows", "section", "page", "support",
        "supported", "listed", "include", "each", "every", "explicit", "cite",
    }
    return {t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 3 and t not in stop}


def _row_matches_terms(row: dict[str, Any], terms: set[str]) -> bool:
    if not terms:
        return True
    blob = f"{row.get('Field','')} {row.get('Value','')} {row.get('Section','')}".lower()
    return any(t in blob for t in terms)


def _document_label(source: str) -> str:
    name = (source or "").split(" p.")[0]
    name = re.sub(r"^[a-f0-9]{16,}_", "", name)
    return re.sub(r"\.pdf$", "", name, flags=re.I) or "the enrolled document"


def _summary_from_rows(rows: list[tuple[str, str, str, str]]) -> str:
    """Neutral lead sentence describing what the evidence rows state."""
    doc = _document_label(rows[0][3])
    sections = list(dict.fromkeys(s for _, _, s, _ in rows if s and s != "—"))
    highlights = "; ".join(f"**{f}** = {v}" for f, v, _, _ in rows[:3])

    where = f" in {sections[0]}" if len(sections) == 1 else ""
    if len(sections) > 1:
        where = f" across {', '.join(sections[:3])}"

    lead = f"{doc} documents {highlights}{where}."
    if len(rows) > 3:
        lead += f" {len(rows) - 3} further matching row(s) are listed below."
    return lead


def _distinct_sources(rows: list[tuple[str, str, str, str]]) -> list[str]:
    out: list[str] = []
    for _, _, section, src in rows:
        label = f"{section} · {src}" if section and section != "—" else src
        if label not in out:
            out.append(label)
    return out[:3]


def _section_from_body(body: str) -> str:
    m = re.search(r">\s*([A-Z][A-Z0-9 /.-]{2,60}?)\s*\(p\.\d+", body)
    if m:
        return m.group(1).strip()
    m = re.search(r"Section:\s*([^\n]+)", body, re.I)
    if m:
        return m.group(1).strip()
    # Fall back to the first all-caps heading line in the chunk.
    for raw in (body or "").split("\n")[:6]:
        line = raw.strip(" |")
        if 3 <= len(line) <= 60 and line == line.upper() and re.search(r"[A-Z]{3,}", line):
            return line
    return ""


def _page_from_source(source: str) -> int | None:
    if " p." not in source:
        return None
    try:
        return int(source.rsplit(" p.", 1)[-1])
    except ValueError:
        return None


def _row_answer_score(row: dict[str, Any], query: str) -> float:
    tokens = {t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 3}
    field = str(row.get("Field", ""))
    value = str(row.get("Value", ""))
    blob = f"{field} {value} {row.get('Section','')}".lower()
    score = sum(1.0 for t in tokens if t in blob)
    if _has_version_tokens([value]):
        score += 3.0
    if "version" in blob and "supported" in blob:
        score += 2.0
    if _is_noise(field):
        score -= 3.0
    if "table of contents" in blob:
        score -= 4.0
    # Demote rows that ignore the distinctive acronyms/identifiers in the query.
    keys = {t for t in tokens if len(t) <= 8 and any(c.isdigit() for c in t) or t.isupper()}
    keys |= {t for t in re.findall(r"\b[A-Za-z]{2,8}\d*\b", query or "") if t.isupper()}
    for key in {k.lower() for k in keys}:
        if key not in blob:
            score -= 1.5
    if len(value) < 5 and not _has_version_tokens([value]):
        score -= 2.0
    return score
