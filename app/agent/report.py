"""Reports specialists send to the master agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SpecialistTask:
    """Work the master assigns to one specialist."""

    agent: str
    store: str
    query: str
    kind: str = ""
    filters: dict[str, Any] = field(default_factory=dict)
    top_k: int = 8
    parallel: bool = True


@dataclass
class AgentReport:
    """One specialist's answer to the master: evidence from that agent's store."""

    agent: str
    store: str
    query: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    markdown: str = ""
    ok: bool = True
    empty: bool = True
    latency_ms: int = 0
    error: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "store": self.store,
            "query": self.query,
            "hits": len(self.evidence),
            "ok": self.ok,
            "empty": self.empty,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "meta": {k: v for k, v in self.meta.items() if k != "round1"},
        }


def tag_evidence(evidence: list[dict[str, Any]], *, agent: str, store: str, kind: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in evidence:
        row = dict(item)
        row.setdefault("agent", agent)
        row.setdefault("store", store)
        if kind:
            row.setdefault("knowledge_kind", kind)
        out.append(row)
    return out


def merge_evidence(reports: list[AgentReport]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for report in reports:
        for item in report.evidence:
            key = str(item.get("chunk_id") or f"{item.get('source')}|{str(item.get('body', ''))[:80]}")
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out
