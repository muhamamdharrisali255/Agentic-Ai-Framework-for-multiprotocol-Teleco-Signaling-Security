"""Map agent evidence items to UI chunk hits."""

from __future__ import annotations

import re
from typing import Any


def evidence_to_chunks(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map agent evidence to UI chunk hits, ranked by relevance score."""
    ranked = sorted(
        enumerate(evidence or [], 1),
        key=lambda pair: float(pair[1].get("score") or 0),
        reverse=True,
    )
    out: list[dict[str, Any]] = []
    for rank, (_orig_i, ev) in enumerate(ranked, 1):
        source = str(ev.get("source") or "")
        body = str(ev.get("body") or "")
        page = None
        m = re.search(r"p\.(\d+)", source)
        if m:
            page = int(m.group(1))
        file_name = source.split(" p.")[0].strip() if " p." in source else source
        preview = body.replace("\n", " ").strip()
        if len(preview) > 360:
            preview = preview[:360] + "..."
        fs_doc = None
        fm = re.search(r"\bFS\.(11|19|20|21)\b", f"{source}\n{body[:400]}", re.I)
        if fm:
            fs_doc = f"FS.{fm.group(1)}"
        out.append(
            {
                "rank": rank,
                "score": round(float(ev.get("score", 0.0)), 4),
                "chunk_id": str(ev.get("chunk_id") or source or f"evidence-{rank}"),
                "content_type": str(ev.get("type") or "Evidence"),
                "page": page,
                "section": ev.get("section", ""),
                "toc_path": ev.get("toc_path", ""),
                "file_name": file_name or None,
                "table_id": ev.get("table_id"),
                "preview": preview,
                "content": body,
                "fs_doc": fs_doc,
            }
        )
    return out
