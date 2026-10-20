"""LangGraph agent workflow — domain-isolated Observe → Plan → Retrieve → Reflect → Reason.

Enforces architecture boundaries:
  - Theory / K-suite → standards (FS.19) corpus only
  - Operator lookups → IR.21 + graph
  - Detection → ids_rules + attack + tools
  - Live observation → ips_events → correlate → rules
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph

from app.agent.classifier import classify_query, extract_entities
from app.agent.dynamic_planner import plan_specialists
from app.agent.evidence_chunks import evidence_to_chunks
from app.agent.intelligence import assess
from app.agent.knowledge_domains import (
    KnowledgeDomain,
    classify_knowledge_domain,
    domain_as_dict,
)
from app.agent.master import collect_reports, reports_markdown
from app.agent.parser import parse_agent_context
from app.agent.planner import build_plan
from app.agent.query_intent import analyze_intent, select_answer_style
from app.agent.query_scope import infer_scope
from app.agent.pipeline import (
    stage_evaluate,
    stage_observe,
    stage_plan,
    stage_retrieve,
    stage_understand,
)
from app.agent.report import merge_evidence
from app.agent.router import HYBRID, STRUCTURED, choose_route
from app.agent.specialists import SpecialistContext
from app.agent.state import AgentState
from app.agent.standards_synthesis import filter_standards_context, filter_standards_evidence
from app.config.settings import settings
from app.nlp.query_enhancer import get_query_enhancer
from app.retrieval.candidate_selector import get_candidate_selector
from app.retrieval.context_builder import build_context, rerank


def _needs_replan(
    evidence: list[dict[str, Any]],
    domain: KnowledgeDomain,
    replan_count: int,
) -> bool:
    if replan_count >= 1:
        return False
    if not evidence:
        return True
    prose = [e for e in evidence if not e.get("structured")]
    if domain == KnowledgeDomain.STANDARDS:
        std = [e for e in prose if e.get("agent") == "standards" or "standard" in str(e.get("store") or "")]
        return len(std) < 1
    if domain == KnowledgeDomain.DETECTION:
        ids = [e for e in evidence if e.get("agent") == "ids_rules" or e.get("type") == "IDS"]
        return len(ids) < 1
    return len(prose) < 1


def _graph_state(state: AgentState) -> dict[str, Any]:
    return state.__dict__.copy()


def _from_graph_state(data: dict[str, Any]) -> AgentState:
    s = AgentState()
    for k, v in data.items():
        if hasattr(s, k):
            setattr(s, k, v)
    return s


# —— Graph nodes ——


def _decompose_query(query: str) -> list[str]:
    """Split compound compare/against questions into sub-queries for per-leg retrieval."""
    q = (query or "").strip()
    if not q:
        return []
    low = q.lower()
    if " against " in low or " compare " in low or " versus " in low or " vs " in low:
        for sep in (" against ", " versus ", " vs ", " compare "):
            if sep in low:
                parts = re.split(re.escape(sep), q, maxsplit=1, flags=re.I)
                if len(parts) == 2 and all(len(p.strip()) > 8 for p in parts):
                    return [p.strip() for p in parts]
    return []


def node_observe(state: AgentState) -> dict[str, Any]:
    query = state.user_query
    observation = state.agent_context.get("_raw_observation") if state.agent_context else None
    if observation is None and state.agent_context:
        observation = state.agent_context

    observe = stage_observe(query, observation if isinstance(observation, dict) else None)
    return {
        "agent_context": observe.agent_context,
        "detection_rules": observe.detection_rules,
        "tools_used": list(dict.fromkeys(list(state.tools_used) + observe.tools_used)),
        "pipeline_mode": observe.pipeline_mode.value,
        "ids_verification": observe.ids_verification,
        "stages": state.stages + ["observe"],
    }


def node_understand(state: AgentState) -> dict[str, Any]:
    query = state.user_query
    document = state.agent_context.get("_document")
    understand = stage_understand(query, state.agent_context, document=document)

    return {
        "enhanced_query": understand.enhanced_query,
        "expanded_terms": understand.expanded_terms,
        "entities": understand.entities,
        "query_type": understand.query_type,
        "candidate_sources": understand.candidate_sources,
        "candidate_filter": understand.candidate_filter,
        "agent_context": {
            **state.agent_context,
            "_scope": understand.scope,
            "_document": document,
            "_sub_queries": understand.sub_queries,
            "_pipeline_mode": state.pipeline_mode,
        },
        "stages": state.stages + ["understand"],
    }


def node_plan(state: AgentState) -> dict[str, Any]:
    query = state.user_query
    ctx = state.agent_context
    understand = stage_understand(query, ctx, document=ctx.get("_document"))
    top_k = int(ctx.get("_top_k") or settings.retrieval_top_k)

    plan_result = stage_plan(
        query,
        understand,
        ctx,
        history=ctx.get("_history"),
        top_k=top_k,
        pipeline_mode=state.pipeline_mode or ctx.get("_pipeline_mode"),
    )
    intent = plan_result.intent

    return {
        "route": plan_result.route,
        "plan": plan_result.plan,
        "specialists": plan_result.specialists,
        "knowledge_kinds": plan_result.knowledge_kinds,
        "candidate_sources": plan_result.candidate_sources,
        "agent_context": {
            **ctx,
            "_intent": intent.intent.value,
            "_intent_profile": {
                "needs_synthesis": intent.needs_synthesis,
                "vector_top_k_multiplier": intent.vector_top_k_multiplier,
            },
            "_search_query": plan_result.search_query,
            "_filters": plan_result.filters,
            "_tasks": [t.__dict__ for t in plan_result.tasks],
            "_knowledge_domain": plan_result.knowledge_domain.value,
            "_domain_meta": domain_as_dict(plan_result.knowledge_domain),
            "_vector_k": top_k,
        },
        "stages": state.stages + ["plan"],
    }


def _report_dict(r) -> dict[str, Any]:
    return {
        **r.as_dict(),
        "evidence": r.evidence,
        "markdown": r.markdown,
        "meta": r.meta,
        "query": r.query,
    }


def node_retrieve(state: AgentState) -> dict[str, Any]:
    from app.agent.knowledge_domains import KnowledgeDomain
    from app.agent.pipeline import PlanResult, stage_retrieve, stage_understand
    from app.agent.report import SpecialistTask

    query = state.user_query
    ctx = state.agent_context
    understand = stage_understand(query, ctx, document=ctx.get("_document"))
    tasks = [SpecialistTask(**t) for t in ctx.get("_tasks") or []]
    plan_result = PlanResult(
        route=state.route,
        plan=state.plan,
        specialists=state.specialists,
        knowledge_kinds=state.knowledge_kinds,
        candidate_sources=state.candidate_sources,
        knowledge_domain=KnowledgeDomain(
            ctx.get("_knowledge_domain") or KnowledgeDomain.STANDARDS.value
        ),
        search_query=ctx.get("_search_query") or query,
        filters=dict(ctx.get("_filters") or {}),
        tasks=tasks,
        intent=None,
    )
    retrieve = stage_retrieve(
        query,
        plan_result,
        understand,
        ctx,
        expanded_terms=state.expanded_terms,
        existing_detection_rules=state.detection_rules,
        existing_tools=state.tools_used,
    )
    return {
        "reports": [_report_dict(r) for r in retrieve.reports],
        "tools_used": retrieve.tools_used,
        "structured_results": retrieve.structured_results,
        "detection_rules": retrieve.detection_rules or state.detection_rules,
        "round1_documents": retrieve.round1_documents,
        "replanned": state.replanned or retrieve.replanned,
        "stages": state.stages + (["replan"] if retrieve.replanned else []) + ["retrieve"],
    }


def node_evaluate(state: AgentState) -> dict[str, Any]:
    from app.agent.knowledge_domains import KnowledgeDomain
    from app.agent.pipeline import PlanResult, RetrieveResult, stage_evaluate, stage_understand
    from app.agent.report import AgentReport, SpecialistTask

    query = state.user_query
    ctx = state.agent_context
    intent_needs = bool((ctx.get("_intent_profile") or {}).get("needs_synthesis"))
    understand = stage_understand(query, ctx, document=ctx.get("_document"))
    tasks = [SpecialistTask(**t) for t in ctx.get("_tasks") or []]
    plan_result = PlanResult(
        route=state.route,
        plan=state.plan,
        specialists=state.specialists,
        knowledge_kinds=state.knowledge_kinds,
        candidate_sources=state.candidate_sources,
        knowledge_domain=KnowledgeDomain(
            ctx.get("_knowledge_domain") or KnowledgeDomain.STANDARDS.value
        ),
        search_query=ctx.get("_search_query") or query,
        filters=dict(ctx.get("_filters") or {}),
        tasks=tasks,
        intent=None,
    )
    reports = [
        AgentReport(
            agent=r["agent"],
            store=r["store"],
            query=r.get("query") or "",
            evidence=list(r.get("evidence") or []),
            markdown=str(r.get("markdown") or ""),
            ok=bool(r.get("ok", True)),
            empty=bool(r.get("empty", True)),
            meta=dict(r.get("meta") or {}),
        )
        for r in state.reports
    ]
    retrieve = RetrieveResult(
        reports=reports,
        tools_used=state.tools_used,
        round1_documents=state.round1_documents,
        detection_rules=state.detection_rules,
        structured_results=state.structured_results,
        replanned=state.replanned,
    )
    evaluated = stage_evaluate(
        query,
        retrieve,
        plan_result,
        ctx,
        intent_needs_synthesis=intent_needs,
        taxonomy=understand.taxonomy,
        expanded_terms=list(state.expanded_terms or []),
    )
    return {
        "structured_results": evaluated.structured_results,
        "evidence": evaluated.evidence,
        "final_context": evaluated.final_context,
        "detection_rules": evaluated.detection_rules,
        "stages": state.stages + ["evaluate"],
    }


def node_reflect(state: AgentState) -> dict[str, Any]:
    domain = KnowledgeDomain(
        state.agent_context.get("_knowledge_domain") or KnowledgeDomain.STANDARDS.value
    )
    replan_count = int(state.agent_context.get("_replan_count") or 0)
    needs = _needs_replan(state.evidence, domain, replan_count)
    return {
        "agent_context": {
            **state.agent_context,
            "_needs_replan": needs,
        },
        "stages": state.stages + ["reflect"],
    }


def node_replan_widen(state: AgentState) -> dict[str, Any]:
    """Second pass: widen standards retrieval when theory evidence is thin."""
    from app.agent.report import AgentReport, SpecialistTask
    from app.ingestion.knowledge_kind import STANDARD

    query = state.user_query
    ctx = state.agent_context
    domain = KnowledgeDomain(ctx.get("_knowledge_domain") or KnowledgeDomain.STANDARDS.value)
    replan_count = int(ctx.get("_replan_count") or 0) + 1

    if domain != KnowledgeDomain.STANDARDS:
        return {"agent_context": {**ctx, "_replan_count": replan_count}, "replanned": True}

    wide_task = SpecialistTask(
        agent="standards",
        store="vector:standard",
        query=ctx.get("_search_query") or query,
        kind=STANDARD,
        filters={},
        top_k=12,
        parallel=False,
    )
    reports = [
        AgentReport(
            agent=r["agent"],
            store=r["store"],
            query=r.get("query") or "",
            evidence=list(r.get("evidence") or []),
            markdown=str(r.get("markdown") or ""),
            ok=bool(r.get("ok", True)),
            empty=bool(r.get("empty", True)),
            meta=dict(r.get("meta") or {}),
        )
        for r in state.reports
    ]
    agent_ctx = parse_agent_context(query, ctx)
    wide_report = collect_reports(
        [wide_task],
        SpecialistContext(
            query=query,
            search_query=ctx.get("_search_query") or query,
            document=ctx.get("_document"),
            entities=state.entities,
            agent_ctx=agent_ctx,
            expanded_terms=state.expanded_terms,
            pipeline_mode=str(ctx.get("_pipeline_mode") or state.pipeline_mode or ""),
        ),
    )
    reports.extend(wide_report)
    evidence = merge_evidence(reports)
    prose = [e for e in evidence if not e.get("structured")]
    std = [e for e in prose if e.get("agent") == "standards"]
    final = (std + [e for e in prose if e.get("agent") != "standards"])[:14]

    return {
        "reports": [_report_dict(r) for r in reports],
        "evidence": final,
        "final_context": state.final_context + "\n\n" + build_context(final),
        "replanned": True,
        "agent_context": {**ctx, "_replan_count": replan_count},
        "stages": state.stages + ["replan"],
    }


def node_correlate(state: AgentState) -> dict[str, Any]:
    query = state.user_query
    agent_ctx = parse_agent_context(query, state.agent_context)
    finding = assess(
        query,
        agent_ctx,
        state.evidence,
        query_type=state.query_type,
        route=state.route.route if state.route else "",
        detection_rules=state.detection_rules,
    )
    return {"finding": finding, "stages": state.stages + ["correlate"]}


def node_reason(state: AgentState) -> dict[str, Any]:
    from app.agent.orchestrator import (
        _extract_suricata_rules_for_ui,
        _finalize_rule_draft,
        _generate_answer,
        _ir21_identity_led,
        _is_followup,
        polish_user_answer,
    )
    from app.agent.faithfulness import check_faithfulness
    from app.agent.parser import parse_agent_context

    query = state.user_query
    ctx = state.agent_context
    intent_val = ctx.get("_intent") or "general"
    intent_profile = ctx.get("_intent_profile") or {}
    domain = KnowledgeDomain(ctx.get("_knowledge_domain") or KnowledgeDomain.STANDARDS.value)

    if not state.evidence:
        return {
            "answer": "Insufficient evidence.",
            "confidence": "INSUFFICIENT",
            "stages": state.stages + ["reason", "respond"],
        }

    has_policy_or_ids = any(
        e.get("type") in ("Message Policy", "IDS") or e.get("agent") in ("policy", "ids_rules")
        for e in state.evidence
    )
    ir21_led = _ir21_identity_led(query, state.route, state.structured_results)
    confidence = state.finding.get("confidence") if state.finding else None
    if not confidence:
        from app.agent.orchestrator import _estimate_confidence

        confidence = _estimate_confidence(state)

    from app.agent.query_intent import QueryIntent

    intent_enum = QueryIntent(intent_val) if intent_val in QueryIntent._value2member_map_ else QueryIntent.GENERAL
    answer_style = select_answer_style(intent_enum, state.evidence)
    qlow = query.lower()
    if any(k in qlow for k in ("detection rule", "create a rule", "draft a rule", "suricata rule", "ids rule")):
        answer_style = "rule_draft"
    elif state.detection_rules:
        from app.agent.rule_composer import should_use_rule_draft

        if should_use_rule_draft(state.detection_rules, parse_agent_context(query, ctx)):
            answer_style = "rule_draft"
    elif state.query_type == "SECURITY_INVESTIGATION" or parse_agent_context(query, ctx).has_observation:
        answer_style = "security_intelligence"
    elif state.structured_results and state.route is not None:
        if state.route.route == STRUCTURED or ir21_led:
            answer_style = "record_lookup"
        elif state.route.route == HYBRID:
            answer_style = "hybrid"

    history = ctx.get("_history")
    answer = _generate_answer(
        query,
        state.final_context,
        history if _is_followup(query) else None,
        answer_style,
        needs_depth=bool(intent_profile.get("needs_synthesis"))
        or answer_style
        in (
            "professional",
            "record_lookup",
            "hybrid",
            "security_intelligence",
            "rule_draft",
        ),
        detection_rules=state.detection_rules if domain != KnowledgeDomain.STANDARDS else [],
        knowledge_domain=domain.value,
        evidence=state.evidence,
    )
    citations = [
        {
            "source_type": e.get("type", ""),
            "source": e.get("source", ""),
            "chunk_id": e.get("chunk_id", ""),
        }
        for e in state.evidence[:8]
    ]

    faith = check_faithfulness(answer, state.evidence)
    if faith.revised_answer:
        answer = faith.revised_answer
    if faith.confidence_override:
        confidence = faith.confidence_override

    detection_rules = list(state.detection_rules or [])
    if answer_style == "rule_draft":
        answer = _finalize_rule_draft(
            answer,
            context=state.final_context or "",
            detection_rules=state.detection_rules if domain != KnowledgeDomain.STANDARDS else [],
        )
        extracted = _extract_suricata_rules_for_ui(answer)
        if extracted:
            detection_rules = extracted
        from app.agent.rule_composer import ensure_summary_section, summarize_defined_rule

        answer = ensure_summary_section(answer, detection_rules)
        for r in detection_rules:
            if isinstance(r, dict) and not r.get("summary"):
                r["summary"] = summarize_defined_rule(r)
    answer = polish_user_answer(answer)

    return {
        "answer": answer,
        "confidence": confidence,
        "citations": citations,
        "detection_rules": detection_rules,
        "agent_context": {
            **state.agent_context,
            "_faithfulness": {
                "faithful": faith.faithful,
                "unsupported_count": len(faith.unsupported),
            },
        },
        "stages": state.stages + ["reason", "verify", "respond"],
    }


def _route_after_reflect(state: AgentState) -> Literal["replan", "correlate"]:
    if state.agent_context.get("_needs_replan"):
        return "replan"
    return "correlate"


def build_agent_graph():
    """Compile the LangGraph workflow."""
    workflow: StateGraph = StateGraph(AgentState)
    workflow.add_node("observe", node_observe)
    workflow.add_node("understand", node_understand)
    workflow.add_node("plan", node_plan)
    workflow.add_node("retrieve", node_retrieve)
    workflow.add_node("evaluate", node_evaluate)
    workflow.add_node("reflect", node_reflect)
    workflow.add_node("replan", node_replan_widen)
    workflow.add_node("correlate", node_correlate)
    workflow.add_node("reason", node_reason)

    workflow.add_edge(START, "observe")
    workflow.add_edge("observe", "understand")
    workflow.add_edge("understand", "plan")
    workflow.add_edge("plan", "retrieve")
    workflow.add_edge("retrieve", "evaluate")
    workflow.add_edge("evaluate", "reflect")
    workflow.add_conditional_edges("reflect", _route_after_reflect, {"replan": "replan", "correlate": "correlate"})
    workflow.add_edge("replan", "correlate")
    workflow.add_edge("correlate", "reason")
    workflow.add_edge("reason", END)
    return workflow.compile()


_COMPILED_GRAPH = None


def get_agent_graph():
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = build_agent_graph()
    return _COMPILED_GRAPH


def run_langgraph_agent(
    query: str,
    *,
    top_k: int = 5,
    document: str | None = None,
    history: list[dict[str, str]] | None = None,
    observation: dict[str, Any] | None = None,
) -> AgentState:
    """Run the LangGraph agent loop."""
    t0 = time.perf_counter()
    initial = AgentState(
        user_query=query,
        trace_id=str(uuid.uuid4())[:12],
        agent_context={
            "_raw_observation": observation,
            "_document": document,
            "_top_k": top_k,
            "_history": history,
            "_replan_count": 0,
        },
    )
    graph = get_agent_graph()
    result = graph.invoke(initial)
    if isinstance(result, AgentState):
        state = result
    elif isinstance(result, dict):
        state = _from_graph_state(result)
    else:
        state = initial
    state.latency_ms = int((time.perf_counter() - t0) * 1000)
    try:
        from app.observability.trace import log_trace
        from app.agent.orchestrator import state_to_response

        log_trace(state_to_response(state) | {"evidence": state.evidence[:12]})
    except Exception:
        pass
    return state
