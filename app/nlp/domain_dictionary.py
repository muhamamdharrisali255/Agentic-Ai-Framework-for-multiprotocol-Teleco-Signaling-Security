"""Domain dictionary (abbreviation → definition). Not a structured knowledge DB.

Terminology lives in data/dictionary/telecom.json so query understanding does
not depend on PostgreSQL. IR.21 remains the only structured store.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config.settings import settings

_DICT_PATH = settings.project_root / "data" / "dictionary" / "telecom.json"


@lru_cache(maxsize=1)
def load_terms() -> list[dict[str, Any]]:
    if _DICT_PATH.is_file():
        try:
            rows = json.loads(_DICT_PATH.read_text(encoding="utf-8"))
            if isinstance(rows, list):
                return [r for r in rows if r.get("term")]
        except Exception:
            pass
    return []


def find_term(token: str) -> dict[str, Any] | None:
    t = (token or "").strip()
    if not t:
        return None
    low = t.lower()
    for row in load_terms():
        if str(row.get("term") or "").lower() == low:
            return row
        aliases = [str(a).lower() for a in (row.get("aliases") or [])]
        if low in aliases:
            return row
    return None


def expand_tokens(tokens: list[str], *, limit: int = 8) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tok in tokens:
        if len(out) >= limit:
            break
        match = find_term(tok)
        if not match:
            continue
        key = str(match["term"]).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(match)
    return out
