"""Per-source-type chunk profiles (implementation_plan.md §9)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ChunkProfile:
    max_chunk_chars: int
    overlap_chars: int
    preserve_tables: bool = True


_DEFAULT = ChunkProfile(max_chunk_chars=800, overlap_chars=80)

_PROFILES: dict[str, ChunkProfile] = {
    "3GPP": ChunkProfile(max_chunk_chars=1200, overlap_chars=120),
    "GSMA": ChunkProfile(max_chunk_chars=900, overlap_chars=90),
    "ETSI": ChunkProfile(max_chunk_chars=1000, overlap_chars=100),
    "RAEX": ChunkProfile(max_chunk_chars=700, overlap_chars=70),
    "IR.21": ChunkProfile(max_chunk_chars=700, overlap_chars=70),
    "policy": ChunkProfile(max_chunk_chars=600, overlap_chars=60),
    "threat": ChunkProfile(max_chunk_chars=500, overlap_chars=50),
    "default": _DEFAULT,
}


def resolve_chunk_profile(
    *,
    source: Optional[str] = None,
    document_type: Optional[str] = None,
    file_name: Optional[str] = None,
) -> ChunkProfile:
    key = (source or document_type or "").upper()
    if key in _PROFILES:
        return _PROFILES[key]
    fn = (file_name or "").lower()
    if "ir21" in fn or "ir.21" in fn or "raex" in fn:
        return _PROFILES["IR.21"]
    if "3gpp" in fn or fn.startswith("ts"):
        return _PROFILES["3GPP"]
    if "gsma" in fn or "fs." in fn:
        return _PROFILES["GSMA"]
    if "policy" in fn or "security" in fn:
        return _PROFILES["policy"]
    return _DEFAULT
