"""Post-generation faithfulness check — flag claims not supported by evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FaithfulnessResult:
    faithful: bool
    unsupported: list[str] = field(default_factory=list)
    revised_answer: str | None = None
    confidence_override: str | None = None


_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")
_CLAIM_BULLET_RE = re.compile(r"^[-*]\s+", re.M)


def _sentences(text: str) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    parts = _SENTENCE_RE.split(text)
    out: list[str] = []
    for block in parts:
        for line in block.split("\n"):
            line = _CLAIM_BULLET_RE.sub("", line).strip()
            if len(line) >= 20:
                out.append(line)
    return out


def _evidence_blob(evidence: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for ev in evidence:
        chunks.append(str(ev.get("body") or ev.get("text") or ""))
        chunks.append(str(ev.get("section") or ""))
        chunks.append(str(ev.get("source") or ""))
    return "\n".join(chunks).lower()


def _claim_supported(claim: str, blob: str) -> bool:
    """Heuristic: at least two content tokens from the claim appear in evidence."""
    tokens = [t for t in re.findall(r"[a-z0-9]{4,}", claim.lower()) if t not in _STOP]
    if not tokens:
        return True
    hits = sum(1 for t in tokens if t in blob)
    return hits >= max(2, len(tokens) // 3)


_STOP = frozenset({
    "that", "this", "with", "from", "they", "their", "there", "which", "would",
    "should", "could", "these", "those", "when", "where", "what", "have", "been",
    "also", "such", "into", "over", "under", "about", "only", "other", "than",
})


def check_faithfulness(
    answer: str,
    evidence: list[dict[str, Any]],
    *,
    max_unsupported: int = 2,
) -> FaithfulnessResult:
    """
    Lightweight critic: identify answer sentences with weak evidence grounding.

    Does not call the LLM — fast enough to run on every response. Unsupported
    claims trigger a confidence downgrade or a brief disclaimer prefix.
    """
    if not answer or not evidence:
        return FaithfulnessResult(faithful=not bool(answer))

    blob = _evidence_blob(evidence)
    unsupported: list[str] = []
    for sent in _sentences(answer):
        if sent.startswith("#") or sent.startswith("**"):
            continue
        if not _claim_supported(sent, blob):
            unsupported.append(sent)

    if len(unsupported) <= max_unsupported:
        return FaithfulnessResult(faithful=True, unsupported=unsupported)

    # Never prepend a disclaimer dump — that pollutes the UI. Downgrade confidence only.
    return FaithfulnessResult(
        faithful=False,
        unsupported=unsupported,
        revised_answer=None,
        confidence_override="LOW",
    )
