"""Agent entrypoint — LangGraph workflow when agentic RAG is enabled."""

from __future__ import annotations

from typing import Any

from app.agent.langgraph_workflow import run_langgraph_agent
from app.agent.orchestrator import run_agent, state_to_response
from app.config.settings import settings


def run_agent_graph(
    query: str,
    *,
    top_k: int = 5,
    document: str | None = None,
    history: list[dict[str, str]] | None = None,
    observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the Observe → Understand → Plan → Retrieve → Reflect → Reason graph."""
    if settings.agentic_rag:
        result = run_langgraph_agent(
            query,
            top_k=top_k or settings.retrieval_top_k,
            document=document,
            history=history,
            observation=observation,
        )
    else:
        result = run_agent(
            query,
            top_k=top_k or settings.retrieval_top_k,
            document=document,
            history=history,
            observation=observation,
        )
    return state_to_response(result)
