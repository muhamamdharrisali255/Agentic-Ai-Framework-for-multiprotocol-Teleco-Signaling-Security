"""Master agent — dynamic plan → dispatch specialists → fuse evidence.

Routing is capability-driven (see dynamic_planner + capability_registry), not
hardcoded question→store maps. New stores are registered as capability cards.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.agent.capability_registry import SPECIALIST_CAPABILITIES, capability_by_agent
from app.agent.dynamic_planner import plan_specialists, suggest_widen
from app.agent.knowledge_domains import is_theory_only_standards_query
from app.agent.parser import AgentContext
from app.agent.report import AgentReport, SpecialistTask, merge_evidence, tag_evidence
from app.agent.router import Route
from app.agent.specialists import SpecialistContext, run_specialist
from app.ingestion.knowledge_kind import STANDARD


_CPU_AGENTS = {c.agent for c in SPECIALIST_CAPABILITIES if c.wave == "cpu"}
_VECTOR_AGENTS = {c.agent for c in SPECIALIST_CAPABILITIES if c.wave == "vector"}
_POST_AGENTS = {c.agent for c in SPECIALIST_CAPABILITIES if c.wave == "post"}


def assign_tasks(
    query: str,
    search_query: str,
    query_type: str,
    route: Route,
    agent_ctx: AgentContext,
    *,
    intent: str = "",
    filters: dict[str, Any] | None = None,
    top_k: int = 8,
    history: list[dict[str, str]] | None = None,
) -> list[SpecialistTask]:
    """Master understands the question + context and picks specialists dynamically."""
    tasks, _decision = plan_specialists(
        query,
        search_query=search_query,
        query_type=query_type,
        route=route,
        agent_ctx=agent_ctx,
        intent=intent,
        history=history,
        filters=filters,
        top_k=top_k,
    )
    return _dedupe(tasks)


def plan_decision(
    query: str,
    search_query: str,
    query_type: str,
    route: Route,
    agent_ctx: AgentContext,
    *,
    intent: str = "",
    filters: dict[str, Any] | None = None,
    top_k: int = 8,
    history: list[dict[str, str]] | None = None,
):
    """Expose the planning decision (agents + scores) for tracing / UI."""
    tasks, decision = plan_specialists(
        query,
        search_query=search_query,
        query_type=query_type,
        route=route,
        agent_ctx=agent_ctx,
        intent=intent,
        history=history,
        filters=filters,
        top_k=top_k,
    )
    return tasks, decision


def specialists_from_tasks(tasks: list[SpecialistTask]) -> list[str]:
    return [t.agent for t in tasks]


def kinds_from_tasks(tasks: list[SpecialistTask]) -> list[str]:
    return [t.kind for t in tasks if t.kind]


def collect_reports(
    tasks: list[SpecialistTask],
    ctx: SpecialistContext,
) -> list[AgentReport]:
    """Run specialists against their stores; widen iteratively if evidence is thin."""
    cpu = [t for t in tasks if t.agent in _CPU_AGENTS]
    vector = [t for t in tasks if t.agent in _VECTOR_AGENTS]
    ids = [t for t in tasks if t.agent in _POST_AGENTS]

    reports: list[AgentReport] = []
    reports.extend(_run_parallel(cpu, ctx) if cpu else [])

    # Graph miss → dynamically add next-best structured/knowledge specialists.
    # Never widen into IR.21 when policy/IDS already cover the question.
    graph_report = next((r for r in reports if r.agent == "graph"), None)
    have = {t.agent for t in tasks}
    policy_led = bool(have & {"policy", "ids_rules"})
    standards_led = is_theory_only_standards_query(ctx.query, agent_ctx=ctx.agent_ctx)
    case_mode = str(ctx.pipeline_mode or "").strip().lower()
    if graph_report and graph_report.meta.get("status") == "NOT_FOUND":
        for agent in suggest_widen(
            list(have),
            ctx.query,
            agent_ctx=ctx.agent_ctx,
            top_n=3,
            pipeline_mode=case_mode,
        ):
            if agent in have:
                continue
            if case_mode in ("case2_rag_chat", "case3_policy_rule") and agent in (
                "policy", "ir21", "ids_rules", "ips_events", "graph", "dictionary"
            ):
                continue
            if standards_led and agent in (
                "policy", "ir21", "ids_rules", "ips_events", "attack", "tools", "graph"
            ):
                continue
            if agent == "ir21" and policy_led:
                continue
            cap = capability_by_agent().get(agent)
            if not cap or cap.wave == "post":
                continue
            if cap.wave == "cpu":
                reports.append(
                    run_specialist(
                        SpecialistTask(
                            agent=cap.agent,
                            store=cap.store,
                            query=ctx.query,
                            top_k=40 if agent == "ir21" else 8,
                            parallel=True,
                        ),
                        ctx,
                    )
                )
                have.add(agent)
            elif cap.wave == "vector" and not any(t.agent == agent for t in vector):
                vector.append(
                    SpecialistTask(
                        agent=cap.agent,
                        store=cap.store,
                        query=ctx.search_query,
                        kind=cap.kind or STANDARD,
                        filters={},
                        top_k=8,
                        parallel=False,
                    )
                )
                have.add(agent)

    for task in vector:
        reports.append(run_specialist(task, ctx))

    empty_vector = [r for r in reports if r.agent in _VECTOR_AGENTS and r.empty and r.ok]
    if empty_vector:
        retries = []
        for report in empty_vector:
            task = next((t for t in vector if t.agent == report.agent), None)
            if not task:
                continue
            wide = SpecialistTask(
                agent=task.agent,
                store=task.store,
                query=task.query,
                kind=task.kind,
                filters={k: v for k, v in task.filters.items() if k not in ("file_name", "file_names")},
                top_k=task.top_k,
                parallel=False,
            )
            retries.append(run_specialist(wide, ctx))
        by_agent = {r.agent: r for r in reports}
        for retry in retries:
            if not retry.empty:
                by_agent[retry.agent] = retry
                retry.meta = {**retry.meta, "widened": True}
        reports = list(by_agent.values())

    still_empty = all(r.empty for r in reports if r.agent in _VECTOR_AGENTS) if vector else False
    if still_empty and vector:
        from app.retrieval.two_stage import round2_chunks

        payload = round2_chunks(
            ctx.search_query,
            filters={
                k: v
                for k, v in (vector[0].filters or {}).items()
                if k not in ("file_name", "file_names", "knowledge_kinds", "knowledge_kind")
            },
            top_k=vector[0].top_k,
        )
        evidence = list(payload.get("evidence") or payload.get("results") or [])
        if evidence:
            reports.append(
                AgentReport(
                    agent="standards",
                    store="vector:standard",
                    query=ctx.search_query,
                    evidence=tag_evidence(
                        evidence, agent="standards", store="vector:standard", kind=STANDARD
                    ),
                    ok=True,
                    empty=False,
                    meta={"fallback": True, "widened": True},
                )
            )

    # Second-chance widen when all CPU specialists returned empty (ambiguous Q).
    if all(r.empty for r in reports if r.agent in _CPU_AGENTS) and reports:
        have_now = {r.agent for r in reports} | have
        policy_led = bool(have_now & {"policy", "ids_rules"})
        standards_led = is_theory_only_standards_query(ctx.query, agent_ctx=ctx.agent_ctx)
        for agent in suggest_widen(
            list(have_now),
            ctx.query,
            agent_ctx=ctx.agent_ctx,
            top_n=2,
            pipeline_mode=case_mode,
        ):
            if agent in have_now:
                continue
            if case_mode in ("case2_rag_chat", "case3_policy_rule") and agent in (
                "policy", "ir21", "ids_rules", "ips_events", "graph", "dictionary"
            ):
                continue
            if standards_led and agent in (
                "policy", "ir21", "ids_rules", "ips_events", "attack", "tools", "graph"
            ):
                continue
            if agent == "ir21" and policy_led:
                continue
            cap = capability_by_agent().get(agent)
            if not cap or cap.wave != "cpu":
                continue
            reports.append(
                run_specialist(
                    SpecialistTask(agent=cap.agent, store=cap.store, query=ctx.query, top_k=8),
                    ctx,
                )
            )

    if ids and not standards_led:
        fused = merge_evidence(reports)
        ids_task = ids[0]
        ids_task.filters = {**ids_task.filters, "prior_evidence": fused}
        reports.append(run_specialist(ids_task, ctx))
    return reports


def reports_markdown(reports: list[AgentReport]) -> str:
    """Fuse specialist markdown: security/policy/ids before IR.21 operator tables."""
    order = {"policy": 0, "ids_rules": 1, "graph": 2, "dictionary": 3, "ips_events": 4, "ir21": 5}
    parts: list[str] = []
    sorted_reports = sorted(reports, key=lambda r: order.get(r.agent, 9))
    has_policy = any(r.agent == "policy" and r.markdown and not r.empty for r in reports)
    has_ids = any(r.agent == "ids_rules" and r.markdown and not r.empty for r in reports)
    has_ir21 = any(r.agent == "ir21" and r.markdown and not r.empty for r in reports)
    # If IR.21 returned network-element / capability rows, keep its brief even when
    # policy was also dispatched (policy often over-fires on GT/HLR wording).
    ir21_priority = False
    if has_ir21:
        for r in reports:
            if r.agent != "ir21":
                continue
            blob = (r.markdown or "") + " ".join(str(e.get("body") or "") for e in r.evidence[:4])
            if any(
                k in blob.lower()
                for k in ("node type", "gt address", "hlr", "msc", "sgsn", "capv", "s6a", "iwf")
            ):
                ir21_priority = True
                break
    for report in sorted_reports:
        if not report.markdown:
            continue
        if report.agent == "ir21" and (has_policy or has_ids) and not ir21_priority:
            # Keep IR.21 out of the fused brief when policy/IDS already answer the intent.
            continue
        if report.agent == "policy" and ir21_priority:
            continue
        if report.agent in order or report.agent in _VECTOR_AGENTS:
            if report.agent in order:
                parts.append(report.markdown)
    return "\n\n".join(p for p in parts if p)


def _run_parallel(tasks: list[SpecialistTask], ctx: SpecialistContext) -> list[AgentReport]:
    if len(tasks) == 1:
        return [run_specialist(tasks[0], ctx)]
    out: list[AgentReport] = []
    with ThreadPoolExecutor(max_workers=min(4, len(tasks))) as pool:
        futures = {pool.submit(run_specialist, task, ctx): task for task in tasks}
        for fut in as_completed(futures):
            out.append(fut.result())
    order = {t.agent: i for i, t in enumerate(tasks)}
    out.sort(key=lambda r: order.get(r.agent, 99))
    return out


def _dedupe(tasks: list[SpecialistTask]) -> list[SpecialistTask]:
    seen: set[str] = set()
    out: list[SpecialistTask] = []
    for task in tasks:
        if task.agent in seen:
            continue
        seen.add(task.agent)
        out.append(task)
    return out
