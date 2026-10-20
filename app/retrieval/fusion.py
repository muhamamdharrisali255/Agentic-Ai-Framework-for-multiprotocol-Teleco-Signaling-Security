"""Cross-source reciprocal rank fusion for hybrid retrieval."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RankedItem:
    """One retrievable unit from any backend (vector, BM25, structured, SQL, …)."""

    item_id: str
    rank: int
    source: str
    score: float = 0.0
    payload: dict[str, Any] = field(default_factory=dict)

    def to_evidence(self) -> dict[str, Any]:
        """Normalize to agent evidence dict."""
        ev = dict(self.payload)
        ev["score"] = self.score
        ev["_fusion_sources"] = list(self.payload.get("_fusion_sources") or [self.source])
        return ev


def reciprocal_rank_fusion(
    ranked_lists: list[list[RankedItem]],
    *,
    k: int = 60,
    top_k: int = 20,
    list_weights: list[float] | None = None,
) -> list[RankedItem]:
    """Fuse multiple ranked lists with RRF. Higher fused score is better."""
    if not ranked_lists:
        return []

    weights = list_weights or [1.0] * len(ranked_lists)
    fused: dict[str, dict[str, Any]] = {}
    for list_idx, items in enumerate(ranked_lists):
        if not items:
            continue
        weight = weights[list_idx] if list_idx < len(weights) else 1.0
        for rank, item in enumerate(items, start=1):
            entry = fused.get(item.item_id)
            if entry is None:
                entry = {
                    "payload": dict(item.payload),
                    "score": 0.0,
                    "sources": set(),
                }
                fused[item.item_id] = entry
            entry["score"] += weight * (1.0 / (k + rank))
            entry["sources"].add(item.source)
            # Keep richest payload (prefer structured body over empty)
            if len(str(item.payload.get("body", ""))) > len(str(entry["payload"].get("body", ""))):
                entry["payload"] = dict(item.payload)

    ordered = sorted(fused.values(), key=lambda x: x["score"], reverse=True)[:top_k]
    out: list[RankedItem] = []
    for i, entry in enumerate(ordered, start=1):
        payload = dict(entry["payload"])
        payload["_fusion_sources"] = sorted(entry["sources"])
        out.append(
            RankedItem(
                item_id=str(payload.get("chunk_id") or payload.get("_id") or i),
                rank=i,
                source="+".join(sorted(entry["sources"])),
                score=float(entry["score"]),
                payload=payload,
            )
        )
    return out


def enforce_min_per_source(
    items: list[RankedItem],
    *,
    min_k: int = 2,
    source_key: str = "file_name",
    top_k: int | None = None,
) -> list[RankedItem]:
    """Guarantee at least min_k hits per document/source in the fused pool (§7.3)."""
    if not items or min_k <= 0:
        return items[: top_k] if top_k else items

    import re

    def _source_label(item: RankedItem) -> str:
        payload = item.payload or {}
        src = str(
            payload.get(source_key)
            or payload.get("source")
            or payload.get("file_name")
            or payload.get("document_id")
            or "unknown"
        )
        m = re.search(r"(FS\.\d+(?:\.\d+)?)", src, re.I)
        if m:
            return m.group(1).upper()
        if "_" in src and src.split("_", 1)[0].isalnum():
            tail = src.split("_", 1)[1]
            if tail.upper().startswith("FS."):
                return tail.split()[0] if tail.split() else tail
        return src.split(" p.")[0].strip() or "unknown"

    by_source: dict[str, list[RankedItem]] = {}
    for item in items:
        src = _source_label(item)
        by_source.setdefault(src, []).append(item)

    picked: list[RankedItem] = []
    seen: set[str] = set()
    # First pass: top min_k per source by fused score.
    for src, group in by_source.items():
        group_sorted = sorted(group, key=lambda x: x.score, reverse=True)
        for item in group_sorted[:min_k]:
            if item.item_id not in seen:
                seen.add(item.item_id)
                picked.append(item)

    # Fill remainder from global ranking.
    for item in sorted(items, key=lambda x: x.score, reverse=True):
        if item.item_id in seen:
            continue
        seen.add(item.item_id)
        picked.append(item)

    if top_k:
        return picked[:top_k]
    return picked
