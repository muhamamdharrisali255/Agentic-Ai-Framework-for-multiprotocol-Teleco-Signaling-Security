"""Unified agent pipeline — imoplementation_plan_updated.md architecture.

Three operating cases:
  CASE1_LIVE_IDS   — IPS agent + operator IDS (CAT detect/block by rule) + rule generator
  CASE2_RAG_CHAT   — Agentic RAG over FS.11 / FS.19 / FS.20 / FS.21 documents
  CASE3_POLICY_RULE — rule agent drafts rules (with summary); new attacks classified from history


Shared stages: observe → understand → plan → retrieve → evaluate → correlate → reason
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.agent.classifier import classify_query, extract_entities
from app.agent.taxonomy_classifier import (
    TaxonomyFacets,
    classify_taxonomy_facets,
    is_policy_instruction,
)
from app.agent.knowledge_domains import (
    KnowledgeDomain,
    classify_knowledge_domain,
    domain_as_dict,
    is_policy_retrieval_query,
    is_qdrant_only_case,
)
from app.agent.master import assign_tasks, collect_reports, reports_markdown
from app.agent.parser import AgentContext, parse_agent_context
from app.agent.planner import build_plan
from app.agent.query_intent import analyze_intent
from app.agent.query_scope import infer_scope
from app.agent.report import merge_evidence
from app.agent.router import HYBRID, STRUCTURED, choose_route
from app.agent.specialists import SpecialistContext
from app.agent.standards_synthesis import filter_standards_context, filter_standards_evidence
from app.config.settings import settings
from app.nlp.query_enhancer import get_query_enhancer
from app.retrieval.candidate_selector import get_candidate_selector
from app.retrieval.context_builder import build_context, evidence_from_tool_result, rerank
import config


class PipelineMode(str, Enum):
    """Operating case from the architecture spec."""

    CASE1_LIVE_IDS = "case1_live_ids"
    CASE2_RAG_CHAT = "case2_rag_chat"
    CASE3_POLICY_RULE = "case3_policy_rule"


_POLICY_MARKERS = re.compile(
    r"\b(block\s+all|enforce|deploy\s+rule|draft\s+(a\s+)?rule|create\s+(a\s+)?rule|"
    r"policy\s+rule|suricata\s+rule|ids\s+rule)\b",
    re.I,
)
_CAT_POLICY_MARKERS = re.compile(r"\bblock\s+all\s+cat(?:egory)?[-\s]?[123]", re.I)


_NEW_ATTACK_MARKERS = re.compile(
    r"\b(new\s+attack|unknown\s+attack|novel\s+attack|classify\s+(this\s+)?attack|"
    r"explain\s+(this\s+)?attack|what\s+attack\s+is\s+this|emerging\s+threat)\b",
    re.I,
)


def classify_pipeline_mode(
    query: str,
    *,
    observation: dict[str, Any] | None = None,
    agent_ctx: AgentContext | None = None,
) -> PipelineMode:
    """Pick Case 1 / 2 / 3 from query + observation."""
    from app.agent.ips_agent import is_raw_ips_payload

    obs = observation or {}
    has_ips = bool(
        agent_ctx
        and (agent_ctx.has_observation or agent_ctx.ips_traffic or agent_ctx.ids_rule)
    )
    if not has_ips and obs:
        has_ips = bool(
            is_raw_ips_payload(obs)
            or obs.get("ips_traffic")
            or obs.get("ids_alerts")
            or obs.get("blocked") is not None
        )

    q = query or ""
    if has_ips:
        return PipelineMode.CASE1_LIVE_IDS
    if is_policy_instruction(q):
        return PipelineMode.CASE3_POLICY_RULE
    if _CAT_POLICY_MARKERS.search(q) or (
        _POLICY_MARKERS.search(q) and re.search(r"\bcat(?:egory)?[-\s]?[123]", q, re.I)
    ):
        return PipelineMode.CASE3_POLICY_RULE
    if _POLICY_MARKERS.search(q) and re.search(
        r"\b(rule|suricata|ids|detection|block|enforce)\b", q, re.I
    ):
        return PipelineMode.CASE3_POLICY_RULE
    if _NEW_ATTACK_MARKERS.search(q):
        return PipelineMode.CASE3_POLICY_RULE
    return PipelineMode.CASE2_RAG_CHAT


@dataclass
class ObserveResult:
    agent_context: dict[str, Any]
    detection_rules: list[dict[str, Any]] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    pipeline_mode: PipelineMode = PipelineMode.CASE2_RAG_CHAT
    ids_verification: dict[str, Any] = field(default_factory=dict)


def stage_observe(
    query: str,
    observation: dict[str, Any] | None = None,
) -> ObserveResult:
    """Agent Parser → IPS capture → IDS Phase-1/2 → enriched AgentContext."""
    from app.agent.ids_engine import run_ids_pipeline
    from app.agent.ips_agent import capture, is_raw_ips_payload
    from app.agent.ips_ids_parser import _rule_action, _rule_payload, _traffic_payload

    tools: list[str] = []
    payload = dict(observation or {})
    cap: dict[str, Any] = {}

    if is_raw_ips_payload(payload) or payload.get("ips_traffic") or payload.get("ids_alerts"):
        if is_raw_ips_payload(payload):
            proto = str(payload.get("protocol") or "")
            cap = capture(payload, protocol=proto)
            base_ctx = dict(cap.get("agent_context") or {})
            tools.append("ips_capture")
        else:
            base_ctx = payload

        agent_ctx = parse_agent_context(query, base_ctx)
        extra = dict(payload)
        extra.update(base_ctx if isinstance(base_ctx, dict) else {})
        ids_result = run_ids_pipeline(agent_ctx, query=query or "What attack is this?", extra=extra)
        rules = list(ids_result.get("detection_rules") or [])
        top = (ids_result.get("phase1") or {}).get("top_rule") or (rules[0] if rules else {})
        action = ids_result.get("ids_action") or _rule_action(top)
        blocked = bool(ids_result.get("blocked"))
        ids_rule = _rule_payload(top)
        if ids_result.get("category") and not ids_rule.get("category"):
            ids_rule["category"] = ids_result.get("category")
        ips_traffic = _traffic_payload(agent_ctx, cap)

        enriched = {
            **agent_ctx.as_dict(),
            "ips_traffic": ips_traffic,
            "ids_rule": ids_rule,
            "ids_action": action,
            "blocked": blocked,
            "category": ids_result.get("category") or ids_rule.get("category") or "",
            "rule_status": ids_rule.get("status") or "",
            "detection_rules": rules[:3],
            "ids_verification": {
                "phase1": ids_result.get("phase1"),
                "phase2": ids_result.get("phase2"),
                "operator_ids": ids_result.get("operator_ids"),
                "confirmed_anomaly": ids_result.get("confirmed_anomaly"),
            },
        }
        if cap.get("event"):
            enriched["ips_event_id"] = str((cap.get("event") or {}).get("event_id") or "")

        mode = PipelineMode.CASE1_LIVE_IDS
        tools.extend(["ips_ids_parser", "ips_agent", "ids_agent", "operator_ids", "ids_phase1", "ids_phase2"])
        if ids_result.get("rule_generator") or ids_result.get("proposed"):
            tools.append("rule_generator")
        return ObserveResult(
            agent_context=enriched,
            detection_rules=rules[:5],
            tools_used=tools,
            pipeline_mode=mode,
            ids_verification=dict(ids_result),
        )

    agent_ctx = parse_agent_context(query, observation)
    mode = classify_pipeline_mode(query, observation=observation, agent_ctx=agent_ctx)
    return ObserveResult(
        agent_context=agent_ctx.as_dict(),
        pipeline_mode=mode,
    )


@dataclass
class UnderstandResult:
    enhanced_query: str
    expanded_terms: list[dict[str, Any]]
    entities: dict[str, Any]
    query_type: str
    candidate_sources: list[str]
    candidate_filter: dict[str, Any]
    scope: dict[str, Any]
    sub_queries: list[str] = field(default_factory=list)
    taxonomy: TaxonomyFacets = field(default_factory=TaxonomyFacets)


def stage_understand(
    query: str,
    agent_context: dict[str, Any],
    *,
    document: str | None = None,
) -> UnderstandResult:
    agent_ctx = parse_agent_context(query, agent_context)
    entities = extract_entities(query)
    entities.update({k: v for k, v in agent_ctx.entity_map().items() if v})
    scope = infer_scope(query, document=document, entities=entities)

    enhancer = get_query_enhancer()
    enhanced = enhancer.enhance(query)
    sub_queries: list[str] = []
    low = query.lower()
    if " against " in low or " compare " in low or " versus " in low or " vs " in low:
        for sep in (" against ", " versus ", " vs ", " compare "):
            if sep in low:
                parts = re.split(re.escape(sep), query, maxsplit=1, flags=re.I)
                if len(parts) == 2 and all(len(p.strip()) > 8 for p in parts):
                    sub_queries = [p.strip() for p in parts]
                break

    cf = get_candidate_selector().select(
        enhanced, classify_query(query, entities, agent_context=agent_ctx), entities
    )
    taxonomy = classify_taxonomy_facets(query)
    return UnderstandResult(
        enhanced_query=enhanced.enhanced_query,
        expanded_terms=[
            {"term": t.term, "definition": t.definition, "domain": t.domain}
            for t in enhanced.expanded_terms
        ],
        entities=entities,
        query_type=classify_query(query, entities, agent_context=agent_ctx),
        candidate_sources=cf.labels(),
        candidate_filter=cf.as_metadata_filters(),
        scope=scope,
        sub_queries=sub_queries,
        taxonomy=taxonomy,
    )


@dataclass
class PlanResult:
    route: Any
    plan: list[str]
    specialists: list[str]
    knowledge_kinds: list[str]
    candidate_sources: list[str]
    knowledge_domain: KnowledgeDomain
    search_query: str
    filters: dict[str, Any]
    tasks: list[Any]
    intent: Any


def stage_plan(
    query: str,
    understand: UnderstandResult,
    agent_context: dict[str, Any],
    *,
    history: list[dict[str, str]] | None = None,
    top_k: int | None = None,
    pipeline_mode: str | PipelineMode | None = None,
) -> PlanResult:
    from app.agent.dynamic_planner import plan_specialists

    agent_ctx = parse_agent_context(query, agent_context)
    intent = analyze_intent(query, understand.query_type)
    route = choose_route(query)
    mode = (
        pipeline_mode.value
        if isinstance(pipeline_mode, PipelineMode)
        else (pipeline_mode or agent_context.get("_pipeline_mode") or "")
    )
    domain = classify_knowledge_domain(
        query,
        route=route,
        agent_ctx=agent_ctx,
        query_type=understand.query_type,
        intent=intent.intent.value,
    )
    # Case 2: standards domain unless the user explicitly asks Suricata/SID tools.
    if mode == PipelineMode.CASE2_RAG_CHAT.value:
        if domain in (KnowledgeDomain.DETECTION, KnowledgeDomain.HYBRID, KnowledgeDomain.OPERATOR):
            if domain == KnowledgeDomain.DETECTION and re.search(
                r"\b(suricata|tshark|wireshark|sid\s*:)\b", (query or "").lower()
            ):
                pass  # keep DETECTION for explicit tool corpus
            else:
                domain = KnowledgeDomain.STANDARDS
    elif mode == PipelineMode.CASE3_POLICY_RULE.value:
        domain = KnowledgeDomain.DETECTION

    plan = build_plan(
        query,
        understand.query_type,
        route,
        agent_ctx,
        intent=intent.intent.value,
        history=history,
    )

    pure_vector = mode in (
        PipelineMode.CASE2_RAG_CHAT.value,
        PipelineMode.CASE3_POLICY_RULE.value,
    )

    # Case 2/3: embed the user's raw question only — no dictionary/taxonomy rewrite.
    if pure_vector:
        search_q = (query or "").strip()
    else:
        search_q = understand.enhanced_query
        if agent_ctx.protocol and agent_ctx.protocol.lower() not in search_q.lower():
            search_q = f"{search_q} {agent_ctx.protocol}"

    filters = dict(understand.candidate_filter) if not pure_vector else {}
    scope = understand.scope
    if pure_vector:
        # Optional UI document pin only (user explicitly selected a file).
        user_doc = (agent_context.get("document") or agent_context.get("file_name") or "").strip()
        if user_doc:
            filters["file_name"] = user_doc
            filters["_user_document_scope"] = True
        filters["_pure_vector"] = True
        if mode == PipelineMode.CASE2_RAG_CHAT.value:
            filters["_knowledge_kind"] = "standard"
            filters["_fs_docs"] = ["FS.11", "FS.19", "FS.20", "FS.21", "FS.22"]
    else:
        tax_hints = understand.taxonomy.as_dict() if understand.taxonomy else {}
        if tax_hints:
            filters["_taxonomy_hints"] = tax_hints
        if scope.get("file_name"):
            filters["file_name"] = scope["file_name"]
        if scope.get("file_names"):
            filters["file_names"] = scope["file_names"]
        if scope.get("tadig"):
            filters["tadig"] = scope["tadig"]
        if scope.get("document_id"):
            filters["document_id"] = scope["document_id"]
        if scope.get("pipelines"):
            filters["pipelines"] = scope["pipelines"]

    k = top_k or settings.retrieval_top_k
    # Pure vector: use requested top_k as-is (no intent multiplier over-fetch games).
    vector_k = k if pure_vector else max(int(k * intent.vector_top_k_multiplier), k)

    tasks, _decision = plan_specialists(
        query,
        search_query=search_q,
        query_type=understand.query_type,
        route=route,
        agent_ctx=agent_ctx,
        intent=intent.intent.value,
        filters=filters,
        top_k=vector_k,
        history=history,
        pipeline_mode=mode,
    )

    # Orchestrator path also uses assign_tasks for compatibility.
    if not tasks:
        tasks = assign_tasks(
            query,
            search_q,
            understand.query_type,
            route,
            agent_ctx,
            intent=intent.intent.value,
            filters=filters,
            top_k=vector_k,
            history=history,
        )
        # Still apply case gate if assign_tasks rebuilt without mode.
        from app.agent.knowledge_domains import filter_agents_by_case
        from app.agent.report import SpecialistTask as _ST

        keep = set(filter_agents_by_case([t.agent for t in tasks], mode))
        tasks = [t for t in tasks if t.agent in keep] or tasks

    return PlanResult(
        route=route,
        plan=plan.steps,
        specialists=[t.agent for t in tasks],
        knowledge_kinds=[t.kind for t in tasks if t.kind],
        candidate_sources=list(
            dict.fromkeys(understand.candidate_sources + plan.sources + [t.store for t in tasks])
        ),
        knowledge_domain=domain,
        search_query=search_q,
        filters=filters,
        tasks=tasks,
        intent=intent,
    )


@dataclass
class RetrieveResult:
    reports: list[Any]
    tools_used: list[str]
    round1_documents: list[dict[str, Any]]
    detection_rules: list[dict[str, Any]]
    structured_results: list[dict[str, Any]]
    replanned: bool


def stage_retrieve(
    query: str,
    plan: PlanResult,
    understand: UnderstandResult,
    agent_context: dict[str, Any],
    *,
    expanded_terms: list[dict[str, Any]] | None = None,
    existing_detection_rules: list[dict[str, Any]] | None = None,
    existing_tools: list[str] | None = None,
) -> RetrieveResult:
    agent_ctx = parse_agent_context(query, agent_context)
    document = agent_context.get("_document")

    reports = collect_reports(
        plan.tasks,
        SpecialistContext(
            query=query,
            search_query=plan.search_query,
            document=document,
            entities=understand.entities,
            agent_ctx=agent_ctx,
            expanded_terms=expanded_terms or [],
            pipeline_mode=str(agent_context.get("_pipeline_mode") or ""),
        ),
    )

    tools = list(existing_tools or [])
    round1: list[dict[str, Any]] = []
    detection_rules = list(existing_detection_rules or [])
    structured_results: list[dict[str, Any]] = []

    for report in reports:
        if report.ok and (not report.empty or report.markdown or report.meta.get("rules")):
            tools.append(report.agent)
        if report.agent == "ir21":
            structured_results = [e for e in report.evidence if e.get("structured")]
        if report.agent == "ids_rules":
            detection_rules = list(report.meta.get("rules") or detection_rules)
        round1.extend(report.meta.get("round1") or [])

    seen_fn: set[str] = set()
    round1_docs: list[dict[str, Any]] = []
    for doc in round1:
        fn = str(doc.get("file_name") or "")
        if fn and fn not in seen_fn:
            seen_fn.add(fn)
            round1_docs.append(doc)

    replanned = any(r.meta.get("widened") or r.meta.get("fallback") for r in reports)
    return RetrieveResult(
        reports=reports,
        tools_used=list(dict.fromkeys(tools)),
        round1_documents=round1_docs,
        detection_rules=detection_rules,
        structured_results=structured_results,
        replanned=replanned,
    )


@dataclass
class EvaluateResult:
    evidence: list[dict[str, Any]]
    structured_results: list[dict[str, Any]]
    final_context: str
    detection_rules: list[dict[str, Any]]


def stage_evaluate(
    query: str,
    retrieve: RetrieveResult,
    plan: PlanResult,
    agent_context: dict[str, Any],
    *,
    intent_needs_synthesis: bool = False,
    taxonomy: TaxonomyFacets | None = None,
    expanded_terms: list[dict[str, Any]] | None = None,
) -> EvaluateResult:
    from app.agent.orchestrator import _ir21_identity_led, _prune_structured_for_query

    agent_ctx = parse_agent_context(query, agent_context)
    domain = plan.knowledge_domain
    scope = agent_context.get("_scope") or {}
    case_mode = str(agent_context.get("_pipeline_mode") or "").strip().lower()
    qdrant_only_case = is_qdrant_only_case(case_mode)

    evidence = merge_evidence(retrieve.reports)
    # Case 2/3: drop SQL/Neo4j specialist dumps from fused evidence; Qdrant stays.
    if qdrant_only_case:
        evidence = [
            e
            for e in evidence
            if e.get("agent") not in ("policy", "ir21", "ids_rules", "graph", "ips_events", "dictionary")
            and e.get("type")
            not in (
                "Message Policy",
                "IDS",
                "Graph Fact",
                "Structured Facts",
                "Structured Database",
                "Structured Record",
                "Domain Dictionary",
            )
        ]
    _struct_prio = {
        "Message Policy": 0,
        "IDS": 1,
        "Graph Fact": 2,
        "Structured Facts": 3,
        "Structured Database": 3,
        "Structured Record": 3,
        "Table": 4,
    }
    structured_all = [e for e in evidence if e.get("structured")]
    if qdrant_only_case:
        structured_all = [e for e in structured_all if e.get("type") == "Table"]
    structured_all.sort(
        key=lambda e: (_struct_prio.get(str(e.get("type") or ""), 9), -float(e.get("score") or 0))
    )

    if qdrant_only_case:
        # Case 2/3: keep retrieval scores, but soft-prefer taxonomy primary FS
        # (e.g. Diameter → FS.19) so FS.11 MAP Cat-2 tables do not dominate.
        tax = taxonomy or classify_taxonomy_facets(query)
        prose_evidence = [e for e in evidence if not e.get("structured")]
        prose_evidence.sort(key=lambda e: float(e.get("score") or 0), reverse=True)
        prose_evidence = _prefer_primary_fs(prose_evidence, tax)
        seen: set[str] = set()
        final_evidence: list[dict[str, Any]] = []
        for e in prose_evidence:
            key = f"{e.get('source')}|{str(e.get('body') or '')[:80]}"
            if key in seen:
                continue
            seen.add(key)
            final_evidence.append(e)
            if len(final_evidence) >= max(int(settings.rerank_top_k or 12), 12):
                break
        # Tables that came from Qdrant chunks only (already filtered above).
        table_pack = _prefer_primary_fs(structured_all[:8], tax)
        for e in table_pack[:4]:
            key = f"{e.get('source')}|{str(e.get('body') or '')[:80]}"
            if key not in seen:
                final_evidence.append(e)
                seen.add(key)
        ctx = build_context(final_evidence)
        return EvaluateResult(
            evidence=final_evidence,
            structured_results=[],
            final_context=ctx,
            detection_rules=[],
        )

    if domain == KnowledgeDomain.STANDARDS:
        from app.agent.standards_synthesis import _is_category_definition_query

        # Definition questions: dictionary + FS + a few policy examples for the LLM.
        if _is_category_definition_query(query):
            policy_ex = [
                e for e in structured_all
                if e.get("type") == "Message Policy"
            ][:3]
            if len(policy_ex) < 2:
                try:
                    from app.ontology.policy_knowledge import search_policy

                    pol = search_policy(query) or {}
                    for row in (pol.get("evidence") or [])[:3]:
                        if row.get("type") == "Message Policy" and row not in policy_ex:
                            policy_ex.append(row)
                except Exception:
                    pass
            tables = [e for e in structured_all if e.get("type") == "Table"]
            structured_all = tables + policy_ex
        else:
            structured_all = [
                e for e in structured_all
                if e.get("type") in ("Table", "Message Policy")
            ]
        prose_evidence = filter_standards_evidence([e for e in evidence if not e.get("structured")])
        if _is_category_definition_query(query):
            prose_evidence = [
                e for e in prose_evidence
                if e.get("type") in ("Domain Dictionary", "Document", "Table")
            ]
    elif domain == KnowledgeDomain.HYBRID or is_policy_retrieval_query(query):
        prose_evidence = [e for e in evidence if not e.get("structured")]
    else:
        prose_evidence = [e for e in evidence if not e.get("structured")]

    # Protocol-knowledge lists need FS docs; parameter lookups keep message_policy.
    qlow = (query or "").lower()
    message_list_q = bool(
        re.search(r"\bwhich\b.*\bmessages?\b", qlow)
        or re.search(r"\b(prohibit\w*|forbidden)\b.*\bmessages?\b", qlow)
        or re.search(r"\bmessages?\b.*\b(prohibit\w*|forbidden)\b", qlow)
    )
    protocol_knowledge = message_list_q or (
        is_policy_retrieval_query(query) and re.search(r"\b(diameter|gtp|ss7|ulr|air)\b", qlow)
    )
    if message_list_q and structured_all:
        policy_rows = [e for e in structured_all if e.get("type") == "Message Policy"][:6]
        if len(policy_rows) < 3:
            try:
                from app.ontology.policy_knowledge import search_policy

                pol = search_policy(query) or {}
                for row in (pol.get("evidence") or [])[:6]:
                    if row.get("type") == "Message Policy" and row not in policy_rows:
                        policy_rows.append(row)
            except Exception:
                pass
        graph_rows = [e for e in structured_all if e.get("type") == "Graph Fact"][:2]
        other_struct = [
            e for e in structured_all
            if e.get("type") not in ("Message Policy", "Graph Fact")
        ]
        structured_all = other_struct + policy_rows + graph_rows
    elif is_policy_retrieval_query(query) and structured_all:
        # Parameter validation: keep Message Policy first (has validation_fields).
        policy_rows = [e for e in structured_all if e.get("type") == "Message Policy"]
        other_struct = [e for e in structured_all if e.get("type") != "Message Policy"]
        structured_all = policy_rows[:5] + other_struct

    if is_policy_retrieval_query(query) or re.search(
        r"\bparameters?\b", qlow
    ) or message_list_q:
        try:
            from app.agent.tools import table_search

            payload = table_search(query, limit=10, pipelines=[config.DOCUMENT_PIPELINE])
            table_rows = evidence_from_tool_result("table_search", payload)
            if table_rows:
                prose_evidence = table_rows + list(prose_evidence)
        except Exception:
            pass

    has_policy_or_ids = any(
        e.get("type") in ("Message Policy", "IDS") or e.get("agent") in ("policy", "ids_rules")
        for e in structured_all
    )
    ir21_led = _ir21_identity_led(query, plan.route, structured_all)

    if has_policy_or_ids and ir21_led:
        structured_all = [
            e for e in structured_all
            if e.get("agent") != "policy" and e.get("type") != "Message Policy"
        ] or structured_all
        has_policy_or_ids = any(
            e.get("type") in ("Message Policy", "IDS") or e.get("agent") in ("policy", "ids_rules")
            for e in structured_all
        )
    elif has_policy_or_ids and not ir21_led and domain != KnowledgeDomain.STANDARDS:
        structured_all = [
            e for e in structured_all
            if e.get("agent") != "ir21" and e.get("store") != "ir21_postgresql"
        ] or structured_all

    structured_all = _prune_structured_for_query(query, structured_all, limit=8)

    scoped_files: list[str] = list(scope.get("file_names") or [])
    if scope.get("file_name"):
        scoped_files.append(scope["file_name"])

    rerank_k = settings.rerank_top_k + (3 if intent_needs_synthesis else 0)
    if domain == KnowledgeDomain.STANDARDS:
        rerank_k += 2
    if message_list_q or domain == KnowledgeDomain.HYBRID:
        rerank_k += 3

    ranked_prose = rerank(
        prose_evidence,
        query,
        top_k=min(rerank_k, 10),
        candidate_scores=scope.get("candidate_scores"),
        scoped_files=scoped_files or None,
        prefer_synthesis=intent_needs_synthesis or (has_policy_or_ids and not ir21_led),
        taxonomy_facets=taxonomy,
    )

    if domain == KnowledgeDomain.STANDARDS:
        ranked_prose = filter_standards_evidence(ranked_prose)
        ranked_prose = [e for e in ranked_prose if e.get("agent") == "standards"] + [
            e for e in ranked_prose if e.get("agent") != "standards"
        ]
    elif protocol_knowledge:
        std_first = [e for e in ranked_prose if e.get("agent") == "standards" or e.get("type") in ("Document", "Table")]
        rest = [e for e in ranked_prose if e not in std_first]
        ranked_prose = std_first + rest

    # Prefer detailed protocol primary (FS.11/19/20) over FS.21 umbrella in the final pack.
    ranked_prose = _prefer_primary_fs(ranked_prose, taxonomy)

    final_evidence = (structured_all + ranked_prose)[:16]
    detection_rules = (
        [] if domain == KnowledgeDomain.STANDARDS else list(retrieve.detection_rules)
    )

    ctx_parts: list[str] = []
    if agent_ctx.as_markdown():
        ctx_parts.append(agent_ctx.as_markdown())
    extra_md = reports_markdown(retrieve.reports)
    if extra_md and domain != KnowledgeDomain.STANDARDS:
        ctx_parts.append(extra_md)
    elif extra_md and domain == KnowledgeDomain.STANDARDS:
        for r in retrieve.reports:
            if r.agent in ("standards", "dictionary") and r.markdown:
                ctx_parts.append(r.markdown)
    ctx_parts.append(build_context(final_evidence))

    final_context = "\n\n".join(p for p in ctx_parts if p)
    if domain == KnowledgeDomain.STANDARDS:
        final_context = filter_standards_context(final_context)

    return EvaluateResult(
        evidence=final_evidence,
        structured_results=structured_all,
        final_context=final_context,
        detection_rules=detection_rules,
    )


def domain_meta(domain: KnowledgeDomain) -> dict[str, Any]:
    return domain_as_dict(domain)


def _prefer_primary_fs(
    evidence: list[dict[str, Any]],
    taxonomy: TaxonomyFacets | None,
) -> list[dict[str, Any]]:
    """Put detailed protocol FS primary chunks ahead of wrong-protocol / umbrella docs."""
    if not evidence:
        return evidence
    primary = ""
    demoted: set[str] = set()
    if taxonomy is not None:
        d = taxonomy.as_dict()
        primary = str(d.get("primary_fs_doc") or "").lower()
        demoted = {str(x).lower() for x in (d.get("demoted_fs_docs") or [])}
    if not primary:
        return evidence

    def _src(e: dict[str, Any]) -> str:
        meta = e.get("metadata") if isinstance(e.get("metadata"), dict) else {}
        return " ".join(
            str(x or "")
            for x in (e.get("source"), e.get("file_name"), meta.get("file_name"), e.get("document_id"))
        ).lower()

    primary_hits = [e for e in evidence if primary in _src(e)]
    secondary = [
        e for e in evidence
        if e not in primary_hits and not any(t in _src(e) for t in demoted)
    ]
    demoted_hits = [e for e in evidence if e not in primary_hits and e not in secondary]
    # When the primary protocol doc is present, do not let demoted FS.* dominate.
    if len(primary_hits) >= 2:
        return primary_hits + secondary + demoted_hits[:1]
    return primary_hits + secondary + demoted_hits[:2]
