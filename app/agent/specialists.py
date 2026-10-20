"""Specialist agents — each queries only its own store and reports to the master.

Stores:
  dictionary  → domain dictionary JSON + taxonomy
  ir21        → PostgreSQL GSMA RAEX IR.21
  graph       → Neo4j ontology (Postgres fallback)
  policy      → message_policy rows (LLM reasons; no canned answers)
  standards   → vector namespace knowledge_kind=standard
  tools       → vector namespace knowledge_kind=tool
  attack      → vector namespace knowledge_kind=attack
  research    → vector namespace knowledge_kind=research
  ips_events  → operational network_events / signaling_event
  ids_rules   → quotes tool+attack reports, cross-checks detection_rule
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from app.agent.parser import AgentContext
from app.agent.report import AgentReport, SpecialistTask, tag_evidence
from app.ingestion.knowledge_kind import ATTACK, RESEARCH, STANDARD, TOOL
from app.retrieval.context_builder import evidence_from_tool_result


@dataclass
class SpecialistContext:
    query: str
    search_query: str
    document: str | None
    entities: dict[str, Any]
    agent_ctx: AgentContext
    expanded_terms: list[dict[str, Any]]
    pipeline_mode: str = ""


_KIND_LABEL = {
    STANDARD: "Document",
    TOOL: "Tool Knowledge",
    ATTACK: "Threat Knowledge",
    RESEARCH: "Document",
}

_KIND_FOCUS = {
    STANDARD: "",
    TOOL: "Suricata TShark IDS signature detection",
    ATTACK: "attack pattern indicators threat",
    RESEARCH: "research survey literature",
}


def run_specialist(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    t0 = time.perf_counter()
    runner = _RUNNERS.get(task.agent)
    if runner is None:
        report = AgentReport(
            agent=task.agent,
            store=task.store,
            query=task.query,
            ok=False,
            error=f"unknown specialist {task.agent}",
        )
    else:
        try:
            report = runner(task, ctx)
        except Exception as exc:
            report = AgentReport(
                agent=task.agent,
                store=task.store,
                query=task.query,
                ok=False,
                error=str(exc),
            )
    report.latency_ms = int((time.perf_counter() - t0) * 1000)
    report.empty = not report.evidence
    return report


def _dictionary(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    from app.agent.tools import dictionary_search
    from app.ontology.taxonomy import categories_for_query, resolve_query_terms

    evidence: list[dict[str, Any]] = []
    used = ""
    for term in [t.get("term") for t in ctx.expanded_terms] or []:
        if not term:
            continue
        payload = dictionary_search(str(term))
        rows = evidence_from_tool_result("dictionary_search", payload)
        if rows:
            evidence.extend(rows)
            used = str(term)
            break
    # Taxonomy / alias hits resolved from the question (Category-1 → CAT1, ULR → …).
    for row in resolve_query_terms(ctx.query):
        term = str(row.get("term") or "")
        definition = str(row.get("definition") or "")
        source = str(row.get("source") or "")
        body = definition if definition.startswith(term) else f"{term}: {definition}"
        evidence.append({
            "type": "Domain Dictionary",
            "source": source or term,
            "body": body,
            "score": 1.5,
        })
        used = used or term
        if len(evidence) >= 8:
            break
    cats = categories_for_query(ctx.query)
    return AgentReport(
        agent="dictionary",
        store="domain_dictionary",
        query=used or task.query,
        evidence=tag_evidence(evidence, agent="dictionary", store="domain_dictionary"),
        ok=True,
        meta={"categories": cats},
    )


def _graph(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    from app.ontology.graph_store import get_ontology_store

    store = get_ontology_store()
    payload = store.query_for_question(ctx.query, ctx.agent_ctx)
    rows = payload.get("rows") or []
    evidence: list[dict[str, Any]] = []
    lines = [f"[Graph facts — {payload.get('template')} / {payload.get('backend')}]"]
    if payload.get("status") == "NOT_FOUND":
        lines.append("- NOT_FOUND: no matching ontology edges; fall back to ir21/standards.")
    for i, row in enumerate(rows[:12]):
        pairs = [f"{k}={v}" for k, v in row.items() if v is not None and v != ""]
        body = "; ".join(pairs)
        evidence.append({
            "type": "Graph Fact",
            "source": f"ontology:{payload.get('template')}",
            "body": body,
            "score": 3.2,
            "chunk_id": f"graph:{payload.get('template')}:{i}",
            "structured": True,
        })
        lines.append(f"- {body}")
    lines.append("[/Graph facts]")
    return AgentReport(
        agent="graph",
        store="neo4j_ontology" if store.is_available() else "postgres_ontology",
        query=ctx.query,
        evidence=tag_evidence(evidence, agent="graph", store="neo4j_ontology"),
        markdown="\n".join(lines) if rows or payload.get("status") == "NOT_FOUND" else "",
        ok=bool(payload.get("ok", True)),
        empty=not evidence,
        error=str(payload.get("error") or ""),
        meta={
            "template": payload.get("template"),
            "status": payload.get("status"),
            "backend": payload.get("backend"),
            "params": payload.get("params") or {},
        },
    )


def _policy(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    from app.ontology.policy_knowledge import search_policy

    payload = search_policy(ctx.query)
    evidence = list(payload.get("evidence") or [])
    lines = ["[Policy knowledge]"]
    for item in evidence[:8]:
        lines.append(f"- {item.get('body')}")
    lines.append("[/Policy knowledge]")
    return AgentReport(
        agent="policy",
        store="message_policy+taxonomy",
        query=ctx.query,
        evidence=tag_evidence(evidence, agent="policy", store="message_policy+taxonomy"),
        markdown="\n".join(lines) if evidence else "",
        ok=True,
        empty=not evidence,
        meta={"backend": payload.get("backend")},
    )


def _ir21(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    from app.agent.tools import ir21_search

    payload = ir21_search(ctx.query, top_k=max(task.top_k, 40))
    evidence = list(payload.get("evidence") or [])
    return AgentReport(
        agent="ir21",
        store="ir21_postgresql",
        query=ctx.query,
        evidence=tag_evidence(evidence, agent="ir21", store="ir21_postgresql"),
        markdown=payload.get("markdown") or "",
        ok="error" not in payload,
        error=str(payload.get("error") or ""),
        meta={"queries": payload.get("queries") or []},
    )


def _vector_kind(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    from app.retrieval.two_stage import round1_documents, round1_to_filters, round2_chunks

    kind = task.kind or STANDARD
    query = task.query
    filters = dict(task.filters)
    filters.pop("_hard_scope", None)
    filters["_query"] = query
    round1: list[dict[str, Any]] = []

    # Case 2/3 pure path: raw user query → Qdrant cosine only (no focus append,
    # no Round-1 FS pinning, no kind/file boosts).
    if filters.get("_pure_vector"):
        filters.pop("knowledge_kinds", None)
        filters.pop("file_names", None)
        filters.pop("file_name", None)
        filters.pop("candidate_scores", None)
        filters.pop("_taxonomy_hints", None)
        payload = round2_chunks(query, filters=filters, top_k=task.top_k)
    else:
        focus = _KIND_FOCUS.get(kind, "")
        if focus and focus.lower() not in query.lower():
            query = f"{query} {focus}"
        filters["_query"] = query
        # Soft kind preference only — never a Qdrant must-filter.
        filters["knowledge_kinds"] = [kind]
        round1 = round1_documents(
            query,
            document=ctx.document,
            entities=ctx.entities,
            knowledge_kinds=[kind],
        )
        filters = round1_to_filters(round1, filters)
        payload = round2_chunks(query, filters=filters, top_k=task.top_k)

    evidence = list(payload.get("evidence") or payload.get("results") or [])
    label = _KIND_LABEL.get(kind, "Document")
    for item in evidence:
        item["type"] = item.get("type") or label
        if kind in (TOOL, ATTACK):
            item["type"] = label
    return AgentReport(
        agent=task.agent,
        store=task.store,
        query=query,
        evidence=tag_evidence(evidence, agent=task.agent, store=task.store, kind=kind),
        ok=True,
        meta={"round1": round1, "kind": kind, "pure_vector": bool(filters.get("_pure_vector"))},
    )


def _ips_events(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    from app.agent.tools import event_search

    sub_id = ctx.entities.get("subscriber_id") or ctx.agent_ctx.subscriber or None
    proto = ctx.entities.get("protocol") or ctx.agent_ctx.protocol or None
    payload = event_search(protocol=proto, subscriber_id=sub_id, limit=10)
    evidence = evidence_from_tool_result("event_search", payload)
    return AgentReport(
        agent="ips_events",
        store="network_events",
        query=f"protocol={proto or ''} subscriber={sub_id or ''}",
        evidence=tag_evidence(evidence, agent="ips_events", store="network_events"),
        ok=True,
    )


def _ids_rules(task: SpecialistTask, ctx: SpecialistContext) -> AgentReport:
    """IDS agent quotes Suricata text; prefers detection_rule table, then vectors."""
    from app.agent.ids_agent import propose_rules

    prior = list(task.filters.get("prior_evidence") or [])
    rules = propose_rules(ctx.agent_ctx, prior, query=ctx.query)
    evidence: list[dict[str, Any]] = []
    lines: list[str] = []
    for rule in rules:
        if rule.get("rule") or rule.get("summary"):
            parts = []
            if rule.get("proposed"):
                parts.append("status=PROPOSED (composed from message_policy + live IPS observation)")
            if rule.get("summary"):
                parts.append(str(rule["summary"]))
            if rule.get("rule"):
                parts.append(str(rule["rule"]))
            if rule.get("note") and rule.get("proposed"):
                parts.append(str(rule["note"]))
            body = "\n".join(parts)
            src = rule.get("source") or "enrolled document"
            evidence.append(
                {
                    "type": "IDS",
                    "source": src,
                    "body": body,
                    "score": 3.0 if rule.get("grounded") else 0.5,
                    "agent": "ids_rules",
                    "store": "derived:tool+attack",
                }
            )
            lines.append(f"- {body} ({src})")
        elif rule.get("note"):
            lines.append(f"- {rule['note']}")
    markdown = ""
    if lines:
        markdown = "[Detection rules from retrieved knowledge]\n" + "\n".join(lines) + "\n[/Detection rules]"
    return AgentReport(
        agent="ids_rules",
        store="derived:tool+attack",
        query=task.query,
        evidence=tag_evidence(evidence, agent="ids_rules", store="derived:tool+attack", kind=TOOL),
        markdown=markdown,
        ok=True,
        meta={"rules": rules},
    )


_RUNNERS = {
    "dictionary": _dictionary,
    "ir21": _ir21,
    "graph": _graph,
    "policy": _policy,
    "standards": _vector_kind,
    "tools": _vector_kind,
    "attack": _vector_kind,
    "research": _vector_kind,
    "ips_events": _ips_events,
    "ids_rules": _ids_rules,
}
