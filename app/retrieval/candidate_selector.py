"""Candidate Source Selector (implementation_plan.md §21)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from app.config.settings import settings
from app.nlp.query_enhancer import EnhancedQuery

QUERY_TYPES = (
    "DOCUMENT_KNOWLEDGE",
    "STRUCTURED_LOOKUP",
    "THREAT_ANALYSIS",
    "SUBSCRIBER_ANALYSIS",
    "SESSION_ANALYSIS",
    "SECURITY_INVESTIGATION",
    "MIXED",
)


@dataclass
class CandidateFilter:
    sources: list[str] | None = None
    series: list[str] | None = None
    domains: list[str] | None = None
    protocols: list[str] | None = None
    max_sources: int = 6
    confidence: float = 0.0
    widen: bool = False

    def as_metadata_filters(self) -> dict[str, Any]:
        """Return only non-restrictive hints — never hard-filter by protocol/domain (§7.2)."""
        if self.widen:
            return {}
        out: dict[str, Any] = {}
        if self.sources:
            out["sources"] = self.sources[: self.max_sources]
        if self.series:
            out["series"] = self.series
        return out

    def labels(self) -> list[str]:
        labels = []
        for s in self.series or []:
            labels.append(f"3GPP series {s}")
        for p in self.protocols or []:
            labels.append(p)
        for d in self.domains or []:
            labels.append(d)
        for s in self.sources or []:
            labels.append(s)
        return labels[: self.max_sources]


class CandidateSourceSelector:
    """Metadata-filter mode — widens on low confidence."""

    _PROTOCOLS = ("SS7", "DIAMETER", "GTP", "GTP-U", "SIP", "S6A", "MAP", "SCCP")
    _DOMAINS = {
        "threat": "telecom_security",
        "attack": "telecom_security",
        "security": "telecom_security",
        "roaming": "roaming",
        "tadig": "roaming",
        "ir.21": "roaming",
        "raex": "roaming",
        "subscriber": "operations",
        "session": "operations",
        "alert": "telecom_security",
        "ids": "telecom_security",
    }

    def select(
        self,
        enhanced: EnhancedQuery,
        query_type: str,
        entities: dict[str, Any] | None = None,
    ) -> CandidateFilter:
        text = f"{enhanced.enhanced_query} {enhanced.original_query}".lower()
        entities = entities or {}
        protocols: list[str] = []
        series: list[str] = []
        sources: list[str] = []
        domains: list[str] = []
        confidence = 0.0

        for p in self._PROTOCOLS:
            if p.lower() in text.replace("-", " "):
                protocols.append(p if p != "GTP-U" else "GTP")
                confidence += 0.25

        for m in re.finditer(r"\b3gpp\b|\bts\s*(\d{2})", text):
            sources.append("3GPP")
            confidence += 0.2
            sm = re.search(r"(\d{2})", m.group(0))
            if sm:
                series.append(sm.group(1))

        for m in re.finditer(r"\bseries\s*(\d{1,2})\b", text):
            series.append(m.group(1).zfill(2))
            confidence += 0.2

        for kw, dom in self._DOMAINS.items():
            if kw in text:
                domains.append(dom)
                confidence += 0.15

        if "gsma" in text or "fs." in text:
            sources.append("GSMA")
            confidence += 0.15
        if "etsi" in text:
            sources.append("ETSI")
            confidence += 0.15
        if any(k in text for k in ("tshark", "t-shark", "wireshark", "suricata")):
            sources.append("TOOL")
            domains.append("telecom_security")
            confidence += 0.2
        if any(k in text for k in ("threat intel", "attack pattern", "ti feed")):
            sources.append("TI")
            domains.append("telecom_security")
            confidence += 0.2
        if "ir.21" in text or "ir21" in text or "raex" in text:
            domains.append("roaming")
            confidence += 0.2
        if entities.get("tadig"):
            domains.append("roaming")
            confidence += 0.35

        if query_type == "THREAT_ANALYSIS":
            domains.append("telecom_security")
            confidence += 0.2
        elif query_type == "STRUCTURED_LOOKUP":
            confidence += 0.1
        elif query_type == "SECURITY_INVESTIGATION":
            domains.append("telecom_security")
            confidence += 0.15

        if entities.get("protocol"):
            protocols.append(str(entities["protocol"]).upper())
            confidence += 0.2

        protocols = list(dict.fromkeys(protocols))
        series = list(dict.fromkeys(series))
        sources = list(dict.fromkeys(sources))
        domains = list(dict.fromkeys(domains))

        widen = confidence < settings.candidate_selector_min_confidence
        if widen:
            return CandidateFilter(
                confidence=confidence,
                widen=True,
                max_sources=settings.candidate_selector_max_sources,
            )

        return CandidateFilter(
            sources=sources or None,
            series=series or None,
            domains=domains or None,
            protocols=protocols or None,
            max_sources=settings.candidate_selector_max_sources,
            confidence=min(confidence, 1.0),
            widen=False,
        )


def get_candidate_selector() -> CandidateSourceSelector:
    return CandidateSourceSelector()
