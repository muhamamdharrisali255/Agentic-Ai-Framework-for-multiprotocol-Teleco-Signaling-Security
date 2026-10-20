"""Query / task planner — roster of specialists chosen dynamically by the Master."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.agent.master import kinds_from_tasks, plan_decision, specialists_from_tasks
from app.agent.parser import AgentContext
from app.agent.router import Route


@dataclass
class InvestigationPlan:
    steps: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    reason: str = ""
    uses_documents: bool = True
    uses_ir21: bool = False
    uses_events: bool = False
    uses_tools: bool = False
    specialists: list[str] = field(default_factory=list)
    knowledge_kinds: list[str] = field(default_factory=list)
    plan_scores: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "sources": self.sources,
            "reason": self.reason,
            "uses_documents": self.uses_documents,
            "uses_ir21": self.uses_ir21,
            "uses_events": self.uses_events,
            "uses_tools": self.uses_tools,
            "specialists": self.specialists,
            "knowledge_kinds": self.knowledge_kinds,
            "plan_scores": self.plan_scores,
        }


def build_plan(
    query: str,
    query_type: str,
    route: Route,
    agent_ctx: AgentContext,
    *,
    intent: str = "",
    history: list[dict[str, str]] | None = None,
) -> InvestigationPlan:
    tasks, decision = plan_decision(
        query,
        query,
        query_type,
        route,
        agent_ctx,
        intent=intent,
        history=history,
    )
    specialists = specialists_from_tasks(tasks)
    kinds = kinds_from_tasks(tasks)
    sources = [t.store for t in tasks]
    return InvestigationPlan(
        steps=specialists,
        sources=list(dict.fromkeys(sources)),
        reason=decision.reason or _reason(query_type, route, agent_ctx, specialists),
        uses_documents=any(k for k in kinds) or route.uses_documents,
        uses_ir21="ir21" in specialists,
        uses_events="ips_events" in specialists or agent_ctx.has_observation,
        uses_tools="tools" in specialists or "ids_rules" in specialists,
        specialists=specialists,
        knowledge_kinds=kinds,
        plan_scores=dict(decision.scores),
    )


def _reason(query_type: str, route: Route, ctx: AgentContext, specialists: list[str]) -> str:
    bits = [f"type={query_type}", f"route={route.route}", "agents=" + ",".join(specialists)]
    if ctx.has_observation:
        bits.append("observed-network-context")
    return "; ".join(bits)
