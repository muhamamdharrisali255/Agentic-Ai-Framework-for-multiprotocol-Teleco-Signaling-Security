"""Maximal marginal relevance — reduce near-duplicate chunks after fusion."""

from __future__ import annotations

import re
from typing import Any


def _token_set(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) >= 3}


def _similarity(a: str, b: str) -> float:
    ta, tb = _token_set(a), _token_set(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _evidence_key(ev: dict[str, Any]) -> str:
    return "|".join(
        str(ev.get(k) or "")
        for k in ("chunk_id", "source", "section", "type")
    ).lower()


def maximal_marginal_relevance(
    items: list[dict[str, Any]],
    *,
    top_k: int,
    lambda_mult: float = 0.7,
) -> list[dict[str, Any]]:
    """
    Re-rank fused evidence for diversity.

    Uses lexical Jaccard on body text — cheap and effective for duplicate chunks
    from the same FS section dominating top-k.
    """
    if not items or top_k <= 0:
        return []
    if len(items) <= top_k:
        return list(items)

    lam = max(0.0, min(1.0, float(lambda_mult)))
    pool = list(items)
    selected: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    # Seed with highest-scoring item.
    pool.sort(key=lambda x: float(x.get("score") or 0), reverse=True)
    first = pool.pop(0)
    selected.append(first)
    seen_keys.add(_evidence_key(first))

    bodies = [str(first.get("body") or first.get("text") or "")]
    while pool and len(selected) < top_k:
        best_idx = -1
        best_score = float("-inf")
        for i, cand in enumerate(pool):
            key = _evidence_key(cand)
            if key in seen_keys:
                continue
            rel = float(cand.get("score") or 0)
            body = str(cand.get("body") or cand.get("text") or "")
            max_sim = max((_similarity(body, b) for b in bodies), default=0.0)
            mmr = lam * rel - (1.0 - lam) * max_sim
            if mmr > best_score:
                best_score = mmr
                best_idx = i
        if best_idx < 0:
            break
        pick = pool.pop(best_idx)
        selected.append(pick)
        seen_keys.add(_evidence_key(pick))
        bodies.append(str(pick.get("body") or pick.get("text") or ""))

    return selected
