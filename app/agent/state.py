"""Agent state (implementation_plan.md §17)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentState:
    user_query: str = ""
    enhanced_query: str = ""
    expanded_terms: list[dict[str, Any]] = field(default_factory=list)
    query_type: str = "DOCUMENT_KNOWLEDGE"
    entities: dict[str, Any] = field(default_factory=dict)
    candidate_sources: list[str] = field(default_factory=list)
    candidate_filter: dict[str, Any] = field(default_factory=dict)
    plan: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    agent_context: dict[str, Any] = field(default_factory=dict)
    round1_documents: list[dict[str, Any]] = field(default_factory=list)
    finding: dict[str, Any] = field(default_factory=dict)
    replanned: bool = False
    specialists: list[str] = field(default_factory=list)
    knowledge_kinds: list[str] = field(default_factory=list)
    detection_rules: list[dict[str, Any]] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)
    #: Chosen retrieval mechanism (app.agent.router.Route).
    route: Any = None
    vector_results: list[dict[str, Any]] = field(default_factory=list)
    structured_results: list[dict[str, Any]] = field(default_factory=list)
    #: SQL issued against the IR.21 relations, for evidence and tracing.
    sql_queries: list[dict[str, Any]] = field(default_factory=list)
    sql_results: list[dict[str, Any]] = field(default_factory=list)
    threat_results: list[dict[str, Any]] = field(default_factory=list)
    event_results: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    final_context: str = ""
    answer: str = ""
    citations: list[dict[str, Any]] = field(default_factory=list)
    confidence: str = "INSUFFICIENT"
    trace_id: str = ""
    latency_ms: int = 0
    #: Operating case: case1_live_ids | case2_rag_chat | case3_policy_rule
    pipeline_mode: str = ""
    ids_verification: dict[str, Any] = field(default_factory=dict)
