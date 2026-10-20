"""Specialist dispatcher — master roster: who owns which store."""

from __future__ import annotations

from app.agent.master import assign_tasks, kinds_from_tasks, specialists_from_tasks
from app.agent.parser import AgentContext
from app.agent.router import Route


def dispatch(
    query: str,
    query_type: str,
    route: Route,
    agent_ctx: AgentContext,
    *,
    intent: str = "",
    search_query: str | None = None,
    filters: dict | None = None,
    top_k: int = 8,
) -> dict:
    tasks = assign_tasks(
        query,
        search_query or query,
        query_type,
        route,
        agent_ctx,
        intent=intent,
        filters=filters,
        top_k=top_k,
    )
    specialists = specialists_from_tasks(tasks)
    kinds = kinds_from_tasks(tasks)
    return {
        "specialists": specialists,
        "knowledge_kinds": kinds,
        "tasks": tasks,
        "investigate": "ids_rules" in specialists,
    }
