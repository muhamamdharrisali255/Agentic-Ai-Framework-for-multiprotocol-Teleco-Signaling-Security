"""Dynamic Master planner — select specialists from intent + context, not keywords.

Scores each registered capability against the question (embeddings when available,
lexical overlap otherwise), applies soft priors from route evidence and observed
network context, and returns a multi-agent roster. Combinations are discovered,
never hardcoded.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from app.agent.capability_registry import SPECIALIST_CAPABILITIES, SpecialistCapability
from app.agent.knowledge_domains import (
    CASE_AGENTS,
    CASE_SQL_AGENTS,
    KnowledgeDomain,
    apply_domain_constraints,
    classify_knowledge_domain,
    filter_agents_by_case,
    filter_agents_by_domain,
)
from app.agent.parser import AgentContext
from app.agent.report import SpecialistTask
from app.agent.router import Route, is_policy_led_query
from app.ontology.taxonomy import metadata_filters_for_query


@dataclass
class PlanDecision:
    agents: list[str]
    scores: dict[str, float] = field(default_factory=dict)
    reason: str = ""
    iterative: bool = False
    knowledge_domain: str = ""


_TOKEN = re.compile(r"[a-z0-9][a-z0-9./_-]{1,}", re.I)
_STOP = {
    "the", "a", "an", "is", "are", "was", "were", "be", "to", "of", "in", "on",
    "for", "and", "or", "what", "which", "how", "why", "when", "where", "does",
    "do", "did", "this", "that", "with", "from", "about", "should", "must",
}


def plan_specialists(
    query: str,
    *,
    search_query: str = "",
    query_type: str = "",
    route: Route | None = None,
    agent_ctx: AgentContext | None = None,
    intent: str = "",
    history: list[dict[str, str]] | None = None,
    filters: dict[str, Any] | None = None,
    top_k: int = 8,
    min_score: float = 0.30,
    max_specialists: int = 8,
    pipeline_mode: str | None = None,
) -> tuple[list[SpecialistTask], PlanDecision]:
    """Return SpecialistTasks chosen dynamically for this question + context."""
    ctx_text = _context_text(query, search_query, agent_ctx, history)
    scores = score_capabilities(ctx_text)
    policy_led = is_policy_led_query(query)
    knowledge_domain = classify_knowledge_domain(
        query,
        route=route,
        agent_ctx=agent_ctx,
        query_type=query_type,
        intent=intent,
    )
    # Theory questions use FS standards — not message_policy taxonomy.
    if knowledge_domain == KnowledgeDomain.STANDARDS:
        policy_led = False

    # Soft priors from evidence-driven route / observation / intent class — not keyword maps.
    scores = _apply_priors(
        scores,
        route,
        agent_ctx,
        query_type,
        intent,
        policy_led=policy_led,
        query=query,
        knowledge_domain=knowledge_domain,
    )
    scores = apply_domain_constraints(scores, knowledge_domain, query=query)

    selected = _select(scores, min_score=min_score, max_n=max_specialists)
    mode = (pipeline_mode or "").strip().lower()
    if mode in ("case2_rag_chat", "case3_policy_rule"):
        # Case gate is authoritative — SQL specialists never dispatched.
        selected = filter_agents_by_case(selected, pipeline_mode)
        # Case 2 knowledge / definition / validation: standards only (tools only if asked).
        qlow = (query or "").lower()
        wants_tools = bool(
            re.search(r"\b(suricata|tshark|wireshark|sid\s*:)\b", qlow)
        )
        wants_attack = bool(
            re.search(r"\b(attack|threat|exploit|hijack|dos)\b", qlow)
        )
        if mode == "case2_rag_chat" and not wants_attack and not wants_tools:
            selected = [a for a in selected if a == "standards"] or ["standards"]
        elif mode == "case2_rag_chat" and wants_tools and not wants_attack:
            selected = [a for a in selected if a in ("standards", "tools")] or ["standards", "tools"]
            if "standards" not in selected:
                selected = ["standards"] + selected
    else:
        selected = filter_agents_by_domain(selected, knowledge_domain)
        if "dictionary" not in selected:
            selected = ["dictionary"] + selected
        selected = _drop_ir21_when_policy_leads(selected, scores, route, policy_led=policy_led)
        selected = _drop_policy_when_ir21_leads(selected, scores, route, policy_led=policy_led)
        selected = _drop_ir21_when_ids_leads(selected, scores, query)

    # Case 3 drafting: ensure tools + standards. Case 2 only when user names Suricata/SID.
    qlow = (query or "").lower()
    if mode == "case3_policy_rule" or (
        mode == "case2_rag_chat"
        and re.search(r"\b(suricata|tshark|wireshark|sid\s*:)\b", qlow)
    ):
        allow = CASE_AGENTS.get(mode or "case2_rag_chat", frozenset())
        for extra in ("tools", "standards"):
            if extra not in selected and (not allow or extra in allow):
                selected.append(extra)
        if mode == "case3_policy_rule" and "attack" not in selected and (
            not allow or "attack" in allow
        ):
            selected.append("attack")
        selected = filter_agents_by_case(selected, pipeline_mode or mode)

    decision = PlanDecision(
        agents=selected,
        scores={a: round(scores.get(a, 0.0), 3) for a in selected},
        reason=_reason(selected, scores, route, agent_ctx, knowledge_domain),
        knowledge_domain=knowledge_domain.value,
    )
    tasks = _tasks_from_agents(
        selected,
        query=query,
        search_query=search_query or query,
        filters=filters,
        top_k=top_k,
    )
    return tasks, decision


def suggest_widen(
    current_agents: list[str],
    query: str,
    *,
    agent_ctx: AgentContext | None = None,
    history: list[dict[str, str]] | None = None,
    top_n: int = 2,
    pipeline_mode: str | None = None,
) -> list[str]:
    """Iterative retrieval: next-best specialists not yet tried."""
    scores = score_capabilities(_context_text(query, query, agent_ctx, history))
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    mode = (pipeline_mode or "").strip().lower()
    case_block = CASE_SQL_AGENTS | {"dictionary"} if mode in (
        "case2_rag_chat",
        "case3_policy_rule",
    ) else frozenset()
    out = []
    for agent, _sc in ranked:
        if agent in current_agents or agent in case_block:
            continue
        if mode == "case2_rag_chat" and agent not in CASE_AGENTS.get(mode, frozenset()):
            continue
        out.append(agent)
        if len(out) >= top_n:
            break
    return out


def score_capabilities(text: str) -> dict[str, float]:
    """Score every registered specialist for this text."""
    emb_scores = _embedding_scores(text)
    lex_scores = _lexical_scores(text)
    out: dict[str, float] = {}
    for cap in SPECIALIST_CAPABILITIES:
        emb = emb_scores.get(cap.agent, 0.0)
        lex = lex_scores.get(cap.agent, 0.0)
        # Blend; lexical helps when embedder is cold/unavailable.
        blended = 0.65 * emb + 0.35 * lex if emb > 0 else lex
        out[cap.agent] = blended + cap.baseline
    return out


def _apply_priors(
    scores: dict[str, float],
    route: Route | None,
    agent_ctx: AgentContext | None,
    query_type: str,
    intent: str,
    *,
    policy_led: bool = False,
    query: str = "",
    knowledge_domain: KnowledgeDomain | None = None,
) -> dict[str, float]:
    s = dict(scores)
    qlow = (query or "").lower()
    investigate = query_type in (
        "SECURITY_INVESTIGATION",
        "THREAT_ANALYSIS",
        "SESSION_ANALYSIS",
        "SUBSCRIBER_ANALYSIS",
        "MIXED",
    ) or intent == "investigate"

    if route is not None and route.uses_structured:
        s["ir21"] = s.get("ir21", 0) + 0.35
    if route is not None and route.uses_documents:
        s["standards"] = s.get("standards", 0) + 0.2

    if knowledge_domain == KnowledgeDomain.STANDARDS:
        s["standards"] = s.get("standards", 0) + 0.35
        s["dictionary"] = s.get("dictionary", 0) + 0.1
        for agent in ("policy", "ir21", "graph", "ids_rules", "ips_events", "attack", "research", "tools"):
            s[agent] = s.get(agent, 0) - 0.5

    if policy_led and knowledge_domain != KnowledgeDomain.STANDARDS:
        s["policy"] = s.get("policy", 0) + 0.42
        s["ir21"] = s.get("ir21", 0) - 0.3
        s["graph"] = s.get("graph", 0) + 0.08

    # Detection-rule lookups should not pull IR.21 operator tables.
    if re.search(r"\b(suricata|detection\s+rule|enrolled\s+rule)\b", qlow):
        s["ids_rules"] = s.get("ids_rules", 0) + 0.35
        s["ir21"] = s.get("ir21", 0) - 0.28

    if agent_ctx and agent_ctx.has_observation:
        s["ips_events"] = s.get("ips_events", 0) + 0.45
        s["graph"] = s.get("graph", 0) + 0.25
        s["ids_rules"] = s.get("ids_rules", 0) + 0.25
        s["attack"] = s.get("attack", 0) + 0.15

    if investigate:
        # Threat intel: attack / tools / standards / rules — not identity graph by default.
        for a in ("attack", "tools", "standards", "ids_rules"):
            s[a] = s.get(a, 0) + 0.22
        # Sequence / session / subscriber investigations need graph + runtime context.
        if query_type in (
            "SESSION_ANALYSIS",
            "SUBSCRIBER_ANALYSIS",
            "SECURITY_INVESTIGATION",
        ):
            s["graph"] = s.get("graph", 0) + 0.35
            s["ips_events"] = s.get("ips_events", 0) + 0.28
        elif query_type == "THREAT_ANALYSIS":
            s["graph"] = s.get("graph", 0) - 0.12

    # Runtime store is only useful when something was observed (or investigation needs it).
    if not (agent_ctx and agent_ctx.has_observation) and query_type not in (
        "SESSION_ANALYSIS",
        "SUBSCRIBER_ANALYSIS",
        "SECURITY_INVESTIGATION",
    ):
        s["ips_events"] = s.get("ips_events", 0) - 0.22

    # Cross-domain fusion: strong standards + secondary IR.21 (operator + FS.19 style).
    # Skip when message-policy already dominates (avoid IR.21 crowding).
    if (
        s.get("standards", 0) >= 0.4
        and 0.18 <= s.get("ir21", 0) < 0.4
        and s.get("policy", 0) < s.get("ir21", 0) + 0.08
    ):
        s["ir21"] = s.get("ir21", 0) + 0.1

    # Policy-heavy knowledge questions: avoid IR.21 crowding unless structured route
    # already indicated operator tables, or IR.21 still clearly outscores policy.
    if route is not None and not route.uses_structured:
        pol = s.get("policy", 0)
        ir = s.get("ir21", 0)
        if pol >= 0.32 and pol >= ir:
            s["ir21"] = ir - 0.2

    # Pure structured IR.21 lookups: demote noisy vector/runtime specialists slightly.
    if (
        route is not None
        and route.route == "STRUCTURED"
        and not (agent_ctx and agent_ctx.has_observation)
        and not policy_led
    ):
        for a in ("attack", "tools", "research", "ips_events", "policy"):
            s[a] = s.get(a, 0) - 0.28
        # Extra demotion when the structured hit is an IR.21 table.
        tables = [str(t).lower() for t in (getattr(route, "tables", None) or [])]
        if any(t.startswith("ir21") for t in tables):
            s["policy"] = s.get("policy", 0) - 0.2
            s["ids_rules"] = s.get("ids_rules", 0) - 0.15
            s["ir21"] = s.get("ir21", 0) + 0.15

    # Identity cluster: keep graph and IR.21 competitive together — but not when
    # message-policy / IDS already dominate (rule-gen and policy questions).
    if (
        s.get("graph", 0) >= 0.25
        and s.get("policy", 0) < 0.3
        and s.get("ids_rules", 0) < 0.4
    ):
        s["ir21"] = max(s.get("ir21", 0), min(0.42, s.get("graph", 0) * 0.9))
        s["graph"] = max(s.get("graph", 0), min(s.get("ir21", 0) - 0.02, s.get("graph", 0) + 0.1))

    return s


def _drop_policy_when_ir21_leads(
    selected: list[str],
    scores: dict[str, float],
    route: Route | None,
    *,
    policy_led: bool = False,
) -> list[str]:
    """Drop message-policy when STRUCTURED IR.21 already answers the question."""
    if policy_led:
        return selected
    if "policy" not in selected or "ir21" not in selected:
        return selected
    if route is None or not route.uses_structured:
        return selected
    tables = [str(t).lower() for t in (getattr(route, "tables", None) or [])]
    if not any(t.startswith("ir21") for t in tables):
        return selected
    ir = scores.get("ir21", 0.0)
    pol = scores.get("policy", 0.0)
    if ir >= pol - 0.05:
        return [a for a in selected if a != "policy"]
    return selected


def _drop_ir21_when_policy_leads(
    selected: list[str],
    scores: dict[str, float],
    route: Route | None,
    *,
    policy_led: bool = False,
) -> list[str]:
    """Drop IR.21 when message-policy already answers a knowledge question."""
    if "ir21" not in selected:
        return selected
    if policy_led and "policy" in selected:
        return [a for a in selected if a != "ir21"]
    if route is not None and route.uses_structured:
        return selected
    pol = scores.get("policy", 0.0)
    ir = scores.get("ir21", 0.0)
    # Message-policy roster → prefer policy over IR.21, except identity lookups
    # where graph + IR.21 jointly answer authorization.
    if "policy" in selected and pol >= 0.28:
        if "graph" in selected and ir >= pol - 0.05:
            return selected
        return [a for a in selected if a != "ir21"]
    if "policy" in selected and "ids_rules" in selected and ir < pol + 0.15:
        if "graph" in selected and ir >= 0.35 and pol < 0.3:
            return selected
        return [a for a in selected if a != "ir21"]
    # IDS rule-gen without IR.21 tables
    if "ids_rules" in selected and scores.get("ids_rules", 0) >= 0.4 and ir <= scores.get("ids_rules", 0) + 0.05:
        return [a for a in selected if a != "ir21"]
    return selected


def _drop_ir21_when_ids_leads(
    selected: list[str],
    scores: dict[str, float],
    query: str,
) -> list[str]:
    """Drop IR.21 when the question is a detection-rule lookup."""
    if "ir21" not in selected or "ids_rules" not in selected:
        return selected
    if re.search(r"\b(suricata|detection\s+rule|enrolled\s+rule)\b", (query or "").lower()):
        if scores.get("ids_rules", 0) >= scores.get("ir21", 0) - 0.1:
            return [a for a in selected if a != "ir21"]
    return selected


def _select(scores: dict[str, float], *, min_score: float, max_n: int) -> list[str]:
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    domain = [(a, sc) for a, sc in ranked if a != "dictionary"]
    if not domain:
        return [a for a, _ in ranked[:3]]
    anchor = domain[0][1]
    # Relative band for the primary cluster; then fill with absolute min_score
    # survivors so secondary domains (e.g. IR.21 beside FS.19) are discovered.
    band = max(min_score, anchor - 0.32)
    picked: list[str] = []
    for a, sc in ranked:
        if sc >= band and a not in picked:
            picked.append(a)
    for a, sc in ranked:
        if len(picked) >= max_n:
            break
        if a not in picked and sc >= min_score:
            picked.append(a)
    if len(picked) < 2:
        picked = [a for a, _ in ranked[:3]]
    return picked[:max_n]


def _tasks_from_agents(
    agents: list[str],
    *,
    query: str,
    search_query: str,
    filters: dict[str, Any] | None,
    top_k: int,
) -> list[SpecialistTask]:
    by = {c.agent: c for c in SPECIALIST_CAPABILITIES}
    base_filters = dict(filters or {})
    hints = metadata_filters_for_query(query)
    if hints:
        base_filters["_taxonomy_hints"] = hints
    tasks: list[SpecialistTask] = []
    seen: set[str] = set()
    for name in agents:
        cap = by.get(name)
        if not cap or name in seen:
            continue
        seen.add(name)
        q = query if cap.wave == "cpu" and name == "ir21" else search_query
        if name == "ir21":
            q = query
            tk = max(top_k, 40)
        elif name in ("policy", "graph", "dictionary", "ips_events"):
            q = query if name != "dictionary" else search_query
            tk = top_k
        else:
            q = search_query
            tk = top_k
        tasks.append(
            SpecialistTask(
                agent=cap.agent,
                store=cap.store,
                query=q,
                kind=cap.kind or "",
                filters=dict(base_filters) if cap.wave == "vector" else {},
                top_k=tk,
                parallel=cap.parallel and cap.wave == "cpu",
            )
        )
    return tasks


def _context_text(
    query: str,
    search_query: str,
    agent_ctx: AgentContext | None,
    history: list[dict[str, str]] | None,
) -> str:
    parts = [query or "", search_query or ""]
    if agent_ctx:
        if agent_ctx.protocol:
            parts.append(f"protocol {agent_ctx.protocol}")
        if agent_ctx.has_observation:
            parts.append("observed network signalling event")
            parts.extend(agent_ctx.observations[:6])
        for k, v in (agent_ctx.entity_map() or {}).items():
            if v:
                parts.append(f"{k} {v}")
    if history:
        for turn in history[-4:]:
            role = turn.get("role") or ""
            content = (turn.get("content") or turn.get("text") or "")[:240]
            if content:
                parts.append(f"{role}: {content}")
    return " ".join(p for p in parts if p).strip()


def _lexical_scores(text: str) -> dict[str, float]:
    qtoks = _tokens(text)
    if not qtoks:
        return {c.agent: 0.0 for c in SPECIALIST_CAPABILITIES}
    out: dict[str, float] = {}
    for cap in SPECIALIST_CAPABILITIES:
        dtoks = _tokens(cap.description)
        if not dtoks:
            out[cap.agent] = 0.0
            continue
        inter = len(qtoks & dtoks)
        union = len(qtoks | dtoks) or 1
        jacc = inter / union
        # Coverage of query tokens that appear in description
        cover = inter / max(len(qtoks), 1)
        out[cap.agent] = 0.4 * jacc + 0.6 * cover
    return out


@lru_cache(maxsize=64)
def _capability_embeddings() -> dict[str, tuple[float, ...]] | None:
    try:
        from app.ingestion.embeddings import get_embedding_provider

        prov = get_embedding_provider()
        texts = [c.description for c in SPECIALIST_CAPABILITIES]
        vecs = prov.embed_documents(texts)
        return {
            c.agent: tuple(float(x) for x in vec)
            for c, vec in zip(SPECIALIST_CAPABILITIES, vecs)
        }
    except Exception:
        return None


def _embedding_scores(text: str) -> dict[str, float]:
    caps = _capability_embeddings()
    if not caps:
        return {c.agent: 0.0 for c in SPECIALIST_CAPABILITIES}
    try:
        from app.ingestion.embeddings import get_embedding_provider

        qv = get_embedding_provider().embed_query(text[:1500])
    except Exception:
        return {c.agent: 0.0 for c in SPECIALIST_CAPABILITIES}
    out: dict[str, float] = {}
    for agent, cv in caps.items():
        out[agent] = _cosine(qv, cv)
    return out


def _cosine(a: list[float] | tuple[float, ...], b: list[float] | tuple[float, ...]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return max(0.0, dot / (na * nb))


def _tokens(text: str) -> set[str]:
    out: set[str] = set()
    for t in _TOKEN.findall(text or ""):
        tl = t.lower()
        if len(tl) <= 2 or tl in _STOP:
            continue
        # Digits dilute coverage (GTs, IMSIs, SIDs); keep short codes like s6a.
        if tl.isdigit() and len(tl) > 4:
            continue
        out.add(tl)
    return out


def _reason(
    selected: list[str],
    scores: dict[str, float],
    route: Route | None,
    agent_ctx: AgentContext | None,
    knowledge_domain: KnowledgeDomain | None = None,
) -> str:
    bits = [
        "dynamic=" + ",".join(f"{a}:{scores.get(a, 0):.2f}" for a in selected),
    ]
    if knowledge_domain is not None:
        bits.append(f"domain={knowledge_domain.value}")
    if route:
        bits.append(f"route={route.route}")
    if agent_ctx and agent_ctx.has_observation:
        bits.append("observed-context")
    return "; ".join(bits)
