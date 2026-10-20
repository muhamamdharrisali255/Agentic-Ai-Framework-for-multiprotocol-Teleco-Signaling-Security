"""Table semantic serializer — contextual text for embedding."""

from __future__ import annotations

from shared.schema import TableStructured


def serialize_table_row(
    table: TableStructured,
    row: dict[str, str],
    document_title: str,
    section_title: str,
    row_index: int,
) -> str:
    """Row text with document/section schema context (not an isolated vector)."""
    caption = table.caption or table.table_id
    headers = table.headers or list(row.keys())
    col_line = " | ".join(headers) if headers else ""
    cell_line = " | ".join(str(row.get(h, "")) for h in headers) if headers else ""
    lines = [
        f"Document: {document_title}",
        f"Section: {section_title}",
        "",
        f"Table: {caption}",
        "",
        f"Columns:\n{col_line}" if col_line else "Columns:",
        "",
        f"Row:\n{cell_line}" if cell_line else f"Row {row_index}:",
    ]
    return "\n".join(lines)


def serialize_table_markdown(
    table: TableStructured,
    max_rows: int | None = 8,
    rows: list[dict[str, str]] | None = None,
) -> str:
    """Structured markdown for final answer context.

    Pass ``max_rows=None`` (or an explicit ``rows`` slice) when indexing, so the
    stored table text carries every documented row; the row cap exists only to
    keep prompt context short at answer time.
    """
    if not table.headers:
        return ""
    header_line = "| " + " | ".join(table.headers) + " |"
    sep_line = "| " + " | ".join("---" for _ in table.headers) + " |"
    source = table.rows if rows is None else rows
    selected = source if max_rows is None else source[:max_rows]
    body = []
    for row in selected:
        cells = [str(row.get(h, "")).replace("|", "\\|") for h in table.headers]
        body.append("| " + " | ".join(cells) + " |")
    extra = ""
    if max_rows is not None and len(source) > max_rows:
        extra = f"\n_… {len(source) - max_rows} more rows omitted_"
    return "\n".join([header_line, sep_line] + body) + extra


def split_rows_by_budget(
    table: TableStructured, budget_chars: int
) -> list[list[dict[str, str]]]:
    """Group rows so each rendered part stays within a character budget.

    Large tables are indexed as several linked TABLE parts rather than being
    truncated, so no documented row becomes unsearchable.
    """
    if not table.rows:
        return [[]]
    header_len = sum(len(h) + 3 for h in table.headers) * 2
    parts: list[list[dict[str, str]]] = [[]]
    used = header_len
    for row in table.rows:
        size = sum(len(str(row.get(h, ""))) + 3 for h in table.headers) + 1
        if parts[-1] and used + size > budget_chars:
            parts.append([])
            used = header_len
        parts[-1].append(row)
        used += size
    return parts
