"""Agent Security Intelligence — correlate observation + retrieved evidence.

This is a decision layer over retrieval, not a second knowledge database.
Scores stay conservative: they reflect evidence coverage, not a claim that
the model has proven an attack.
"""

from __future__ import annotations

from typing import Any

from app.agent.parser import AgentContext


_ATTACKISH = (
    "hijack", "abuse", "flood", "spoof", "intercept", "fraud", "injection",
    "tunnel", "teid", "anomaly", "malicious", "exploit",
)


def assess(
    query: str,
    agent_ctx: AgentContext,
    evidence: list[dict[str, Any]],
    *,
    query_type: str = "",
    route: str = "",
    detection_rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    types = {str(e.get("type") or "") for e in evidence}
    sources = [str(e.get("source") or "") for e in evidence if e.get("source")]
    n = len(evidence)
    observed = agent_ctx.has_observation
    investigate = query_type in (
        "SECURITY_INVESTIGATION",
        "THREAT_ANALYSIS",
        "SESSION_ANALYSIS",
    )

    coverage = 0.0
    if n:
        coverage += min(0.45, 0.12 * n)
    if "Document" in types or "Threat Knowledge" in types or "Graph Fact" in types:
        coverage += 0.2
    if any(e.get("structured") for e in evidence):
        coverage += 0.15
    if observed:
        coverage += 0.15
    if "Domain Dictionary" in types:
        coverage += 0.05
    rules = detection_rules or []
    if any(r.get("grounded") for r in rules):
        coverage += 0.08
    coverage = min(coverage, 0.95)

    if n == 0:
        band = "INSUFFICIENT"
        severity = "unknown"
    elif coverage >= 0.7 and (observed or investigate):
        band = "HIGH"
        severity = "high" if observed and _looks_malicious(query, agent_ctx, evidence) else "medium"
    elif coverage >= 0.4:
        band = "MEDIUM"
        severity = "medium" if investigate else "info"
    else:
        band = "LOW"
        severity = "info"

    finding = _finding_line(query, agent_ctx, evidence, investigate, observed)
    recommendation = _recommendation(investigate, observed, n, route)

    return {
        "finding": finding,
        "confidence": band,
        "confidence_score": round(coverage, 2),
        "severity": severity,
        "observed": observed,
        "matched_types": sorted(t for t in types if t),
        "evidence_sources": sources[:8],
        "recommendation": recommendation,
        "detection_rules": rules[:5],
    }


def _looks_malicious(query: str, ctx: AgentContext, evidence: list[dict[str, Any]]) -> bool:
    blob = " ".join(
        [
            query.lower(),
            " ".join(ctx.observations).lower(),
            " ".join(str(e.get("body") or "") for e in evidence[:6]).lower(),
        ]
    )
    return any(w in blob for w in _ATTACKISH)


def _finding_line(
    query: str,
    ctx: AgentContext,
    evidence: list[dict[str, Any]],
    investigate: bool,
    observed: bool,
) -> str:
    if not evidence:
        return "Insufficient evidence to form a security assessment."
    proto = ctx.protocol or ""
    if investigate and observed:
        who = proto or "signalling"
        return (
            f"Observed {who} behaviour requires correlation against standards, "
            "attack patterns, and detection knowledge in the evidence set."
        )
    if investigate:
        return "Security question answered from retrieved standards and threat documents."

    types = {str(e.get("type") or "") for e in evidence}
    if "Domain Dictionary" in types or any(
        "fs." in str(e.get("source") or "").lower() for e in evidence[:6]
    ):
        return "Answered from GSMA category / standards definitions."
    if any(
        e.get("type") == "Message Policy" or str(e.get("agent") or "") == "policy"
        for e in evidence
    ):
        return "Answered from message-policy and standards evidence."
    if any(
        e.get("structured") and e.get("type") not in ("Message Policy", "Table", "IDS")
        for e in evidence
    ):
        return "Answered from GSMA RAEX IR.21 structured records."
    return "Answered from retrieved telecom/security documents."


def _recommendation(investigate: bool, observed: bool, n: int, route: str) -> str:
    if n == 0:
        return "Rephrase the question or enroll the relevant standard / IR.21 filing."
    if investigate and observed:
        return (
            "Validate the session against the cited standard and detection guidance; "
            "confirm identifiers (IMSI, TEID, GT, IPs) on the affected path before acting."
        )
    if route == "STRUCTURED":
        return "Treat IR.21 values as operator-declared configuration, not live network state."
    return "Use the cited sections as the basis for any follow-up check."
