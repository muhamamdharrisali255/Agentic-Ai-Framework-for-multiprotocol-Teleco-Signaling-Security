"""Knowledge-domain classifier — enforces architecture boundaries between stores.

Signaling & Roaming (IR.21, graph, observed traffic) must not bleed into
Network & Security Policy (message_policy) or vice versa for theory questions.
Theory / category / protocol questions are answered from FS standards prose,
not from enrolled taxonomy tables or operator IR.21 rows unless the question
names a specific operator or live observation is present.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from app.agent.capability_registry import SPECIALIST_CAPABILITIES
from app.agent.parser import AgentContext
from app.agent.router import Route


class KnowledgeDomain(str, Enum):
    """Which knowledge path the agent graph should follow."""

    STANDARDS = "standards"  # FS.19 / specification corpus — theory & concepts
    OPERATOR = "operator"  # IR.21 + graph — enrolled operator facts
    DETECTION = "detection"  # IDS rules, Suricata, attack-pattern translation
    INVESTIGATION = "investigation"  # Live/captured traffic → correlate → rules
    HYBRID = "hybrid"  # Explicit cross-domain (structured + documents)


# Agents permitted per domain — everything else is demoted or dropped.
DOMAIN_AGENTS: dict[KnowledgeDomain, frozenset[str]] = {
    KnowledgeDomain.STANDARDS: frozenset({"dictionary", "standards"}),
    KnowledgeDomain.OPERATOR: frozenset(
        {"dictionary", "ir21", "graph"}
    ),
    KnowledgeDomain.DETECTION: frozenset(
        {"dictionary", "ids_rules", "attack", "tools", "standards", "policy"}
    ),
    KnowledgeDomain.INVESTIGATION: frozenset(
        {
            "dictionary",
            "ips_events",
            "graph",
            "ids_rules",
            "attack",
            "standards",
            "tools",
            "policy",
        }
    ),
    KnowledgeDomain.HYBRID: frozenset(c.agent for c in SPECIALIST_CAPABILITIES),
}

# Case allow-lists (architecture Case 1/2/3) — single hard gate.
# Case 1: IPS + operator IDS + rule generator (structured + threat + standards).
# Case 2: Agentic RAG over FS documents only (Qdrant `standards`).
# Case 3: rule agent + attack history (FS + Suricata/attack vectors).
_QDRANT_VECTOR_AGENTS = frozenset({"standards", "tools", "attack", "research"})
CASE_AGENTS: dict[str, frozenset[str]] = {
    "case1_live_ids": frozenset(
        {
            "dictionary",
            "policy",
            "graph",
            "ips_events",
            "ids_rules",
            "attack",
            "tools",
            "standards",
        }
    ),
    "case2_rag_chat": frozenset({"standards"}),
    "case3_policy_rule": _QDRANT_VECTOR_AGENTS,
}

# SQL / structured specialists — never dispatched from Case 2/3 plan.
CASE_SQL_AGENTS = frozenset({"policy", "ir21", "ids_rules", "ips_events", "graph"})

# Deprecated: Case 2 no longer soft-injects SQL/dictionary at evaluate.
CASE2_SOFT_ENRICHMENT = frozenset()


def is_qdrant_only_case(pipeline_mode: str | None) -> bool:
    mode = (pipeline_mode or "").strip().lower()
    return mode in ("case2_rag_chat", "case3_policy_rule")

# Hard blocks — no bridge between roaming inputs and deployed policy for theory.
DOMAIN_BLOCKED: dict[KnowledgeDomain, frozenset[str]] = {
    KnowledgeDomain.STANDARDS: frozenset(
        {"ir21", "policy", "graph", "ips_events", "ids_rules", "attack", "research", "tools"}
    ),
    KnowledgeDomain.OPERATOR: frozenset({"policy", "ids_rules", "ips_events"}),
    KnowledgeDomain.DETECTION: frozenset({"ir21", "graph", "ips_events"}),
}

_OPERATOR_MARKERS = re.compile(
    r"\b(ir\.?\s*21|tadig|zain|kuwait|kwtmt|operator|global\s+title|"
    r"\bgt\b|hlr|hss|msc|vlr|sgsn|mme|capv|camel|s6a|iwf|gsmssf)\b",
    re.I,
)
_DETECTION_MARKERS = re.compile(
    r"\b(suricata|detection\s+rule|ids\s+rule|enrolled\s+rule|attack\s+pattern|"
    r"\bap\d{3}\b|\bdr\d{3}\b|\bsid\b|create\s+a\s+rule|draft\s+a\s+rule)\b",
    re.I,
)
_STANDARDS_MARKERS = re.compile(
    r"\b(what\s+is|what\s+are|explain|describe|define|difference\s+between|"
    r"normally\s+associated|relevant\s+to|how\s+does|how\s+do|why\s+|"
    r"category[-\s]?[123]|cat[-\s]?[123]|prohibit\w*|forbidden|"
    r"validat\w+|parameters?\s+(are|should|used)|protocol|signaling|signalling|"
    r"diameter|ss7|map|gtp|ulr|air|authentication|location\s+management|"
    r"roaming\s+(interface|session)|interconnect)\b",
    re.I,
)
_POLICY_RETRIEVAL = re.compile(
    r"\b(parameters?\s+(are|should|used|to\s+validat)|"
    r"should\s+be\s+validated|validation\s+fields?|"
    r"\bulr\b|\bair\b|create\s+session|update\s*location)\b",
    re.I,
)
_PROTOCOL_MESSAGE_LIST = re.compile(
    r"\bwhich\b.*\b(messages?|diameter|gtp|ss7|map)\b|"
    r"\b(prohibit\w*|forbidden)\b.*\bmessages?\b|"
    r"\bmessages?\b.*\b(prohibit\w*|forbidden)\b",
    re.I,
)
_INVESTIGATE_MARKERS = re.compile(
    r"\b(flagged|suspicious|investigate|anomal|malicious|observed|captured|"
    r"this\s+packet|this\s+traffic|why\s+was|is\s+this)\b",
    re.I,
)


def is_policy_retrieval_query(query: str) -> bool:
    """Parameter / message-policy lookups need message_policy + FS tables, not dictionary alone."""
    return bool(_POLICY_RETRIEVAL.search(query or ""))


def is_theory_only_standards_query(query: str, *, agent_ctx: AgentContext | None = None) -> bool:
    """Standards-only routing (no policy/IR.21) for concept/definition questions."""
    if is_policy_retrieval_query(query) or _PROTOCOL_MESSAGE_LIST.search(query or ""):
        return False
    return is_standards_knowledge_query(query, agent_ctx=agent_ctx)


def is_standards_knowledge_query(query: str, *, agent_ctx: AgentContext | None = None) -> bool:
    """True when the answer should come from FS / standards prose, not policy or IR.21."""
    if agent_ctx and agent_ctx.has_observation:
        return False
    q = query or ""
    if _DETECTION_MARKERS.search(q):
        return False
    if _OPERATOR_MARKERS.search(q) and not _STANDARDS_MARKERS.search(q):
        return False
    return bool(_STANDARDS_MARKERS.search(q))


def classify_knowledge_domain(
    query: str,
    *,
    route: Route | None = None,
    agent_ctx: AgentContext | None = None,
    query_type: str = "",
    intent: str = "",
) -> KnowledgeDomain:
    """Pick the primary knowledge path for this question."""
    q = query or ""
    has_obs = bool(agent_ctx and agent_ctx.has_observation)

    # Live traffic / explicit investigation markers with an observation → investigate.
    # Do NOT let "session" in a theory question (e.g. GTP session establishment)
    # steal routing into ips_events / graph.
    if has_obs and (
        intent == "investigate"
        or _INVESTIGATE_MARKERS.search(q)
        or query_type
        in (
            "SECURITY_INVESTIGATION",
            "SESSION_ANALYSIS",
            "SUBSCRIBER_ANALYSIS",
            "THREAT_ANALYSIS",
        )
    ):
        return KnowledgeDomain.INVESTIGATION

    if not has_obs and _INVESTIGATE_MARKERS.search(q) and query_type in (
        "SECURITY_INVESTIGATION",
        "THREAT_ANALYSIS",
    ):
        return KnowledgeDomain.INVESTIGATION

    if _DETECTION_MARKERS.search(q):
        return KnowledgeDomain.DETECTION

    # Protocol message lists + parameter lookups → hybrid FS primary + policy.
    if is_policy_retrieval_query(q) or _PROTOCOL_MESSAGE_LIST.search(q):
        return KnowledgeDomain.HYBRID

    if is_standards_knowledge_query(q, agent_ctx=agent_ctx):
        return KnowledgeDomain.STANDARDS

    if route is not None and route.uses_structured:
        tables = [str(t).lower() for t in (getattr(route, "tables", None) or [])]
        if any(t.startswith("ir21") for t in tables) or _OPERATOR_MARKERS.search(q):
            return KnowledgeDomain.OPERATOR
        if route.route == "HYBRID":
            return KnowledgeDomain.HYBRID

    if _OPERATOR_MARKERS.search(q):
        return KnowledgeDomain.OPERATOR

    if route is not None and route.uses_documents and not route.uses_structured:
        return KnowledgeDomain.STANDARDS

    return KnowledgeDomain.STANDARDS


def apply_domain_constraints(
    scores: dict[str, float],
    domain: KnowledgeDomain,
    *,
    query: str = "",
) -> dict[str, float]:
    """Boost allowed agents and demote blocked ones for the chosen domain."""
    s = dict(scores)
    allowed = DOMAIN_AGENTS.get(domain, frozenset())
    blocked = DOMAIN_BLOCKED.get(domain, frozenset())

    for agent in allowed:
        s[agent] = s.get(agent, 0) + 0.35
    for agent in blocked:
        s[agent] = s.get(agent, 0) - 0.55

    if domain == KnowledgeDomain.STANDARDS:
        s["standards"] = s.get("standards", 0) + 0.35
        s["dictionary"] = s.get("dictionary", 0) + 0.1
        for agent in ("attack", "research", "tools", "policy", "ids_rules", "ir21", "graph", "ips_events"):
            s[agent] = s.get(agent, 0) - 0.5
        if re.search(r"\b(tshark|wireshark|suricata\s+preprocessor|filter)\b", (query or "").lower()):
            s["tools"] = s.get("tools", 0) + 0.15

    if domain == KnowledgeDomain.OPERATOR:
        s["ir21"] = s.get("ir21", 0) + 0.3
        s["graph"] = s.get("graph", 0) + 0.15
        s["standards"] = s.get("standards", 0) - 0.55

    if domain == KnowledgeDomain.DETECTION:
        s["ids_rules"] = s.get("ids_rules", 0) + 0.35
        s["attack"] = s.get("attack", 0) + 0.15

    if domain == KnowledgeDomain.INVESTIGATION:
        s["ips_events"] = s.get("ips_events", 0) + 0.4
        s["graph"] = s.get("graph", 0) + 0.2
        s["ids_rules"] = s.get("ids_rules", 0) + 0.2

    return s


def filter_agents_by_domain(agents: list[str], domain: KnowledgeDomain) -> list[str]:
    """Drop agents that violate domain isolation."""
    blocked = DOMAIN_BLOCKED.get(domain, frozenset())
    allowed = DOMAIN_AGENTS.get(domain)
    out: list[str] = []
    for a in agents:
        if a in blocked:
            continue
        if allowed is not None and a not in allowed and a != "dictionary":
            continue
        out.append(a)
    if not out or (len(out) == 1 and out[0] == "dictionary"):
        # Always keep at least standards or primary domain agent.
        primary = {
            KnowledgeDomain.STANDARDS: "standards",
            KnowledgeDomain.OPERATOR: "ir21",
            KnowledgeDomain.DETECTION: "ids_rules",
            KnowledgeDomain.INVESTIGATION: "ips_events",
        }.get(domain, "standards")
        if primary not in out:
            out.append(primary)
    return out


def filter_agents_by_case(agents: list[str], pipeline_mode: str | None) -> list[str]:
    """Hard allow-list by Case 1/2/3. Case 2/3 never call SQL specialists."""
    mode = (pipeline_mode or "").strip().lower()
    allowed = CASE_AGENTS.get(mode)
    if allowed is None:
        return list(agents)
    out = [a for a in agents if a in allowed]
    # Case 2/3: never inject dictionary as answer specialist (expansion already ran).
    if mode in ("case2_rag_chat", "case3_policy_rule"):
        out = [a for a in out if a not in CASE_SQL_AGENTS and a != "dictionary"]
        if not out:
            out = ["standards"]
        if "standards" not in out and mode == "case2_rag_chat":
            out = ["standards"] + out
        # Rule / Suricata questions: ensure tools corpus is in the roster.
        return out
    if not out:
        out = ["standards"] if mode != "case1_live_ids" else ["ips_events", "ids_rules"]
    return out


def domain_as_dict(domain: KnowledgeDomain) -> dict[str, Any]:
    return {
        "domain": domain.value,
        "allowed": sorted(DOMAIN_AGENTS.get(domain, frozenset())),
        "blocked": sorted(DOMAIN_BLOCKED.get(domain, frozenset())),
    }
