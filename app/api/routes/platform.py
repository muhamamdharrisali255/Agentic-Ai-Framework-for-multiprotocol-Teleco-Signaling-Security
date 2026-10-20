"""Platform API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.agent.graph import run_agent_graph
from app.agent.orchestrator import run_agent, state_to_response
from app.config.settings import settings
from app.database import postgres, repositories as repo
from app.database.postgres import init_schema
from app.nlp.query_enhancer import get_query_enhancer
from app.retrieval.qdrant_store import get_qdrant_store

router = APIRouter()


class ChatRequest(BaseModel):
    query: str | None = None
    message: str | None = None
    top_k: int = Field(default=5, ge=1, le=20)
    document: str | None = None
    conversation_id: str | None = None
    observation: dict | None = None

    def text(self) -> str:
        return (self.query or self.message or "").strip()


@router.get("/platform/health")
def platform_health():
    qdrant_ok = False
    try:
        qdrant_ok = get_qdrant_store().is_available()
    except Exception:
        pass
    return {
        "ok": True,
        "service": "signaling-firewall",
        "agentic_rag": settings.agentic_rag,
        "postgres": postgres.backend_name(),
        "qdrant": qdrant_ok,
    }


@router.post("/agent/run")
def agent_run(req: ChatRequest):
    q = req.text()
    if not q:
        raise HTTPException(400, "Empty query")
    if settings.agentic_rag:
        return run_agent_graph(
            q, top_k=req.top_k, document=req.document, observation=req.observation
        )
    state = run_agent(
        q, top_k=req.top_k, document=req.document, observation=req.observation
    )
    return state_to_response(state)


class EventIngestRequest(BaseModel):
    protocol: str = "GTP"
    event_type: str = ""
    subscriber_id: str = ""
    session_id: str = ""
    severity: str = "INFO"
    raw: dict = Field(default_factory=dict)
    investigate: bool = False
    query: str | None = None


@router.post("/events")
def ingest_network_event(body: EventIngestRequest):
    from app.agent.ips_ids_parser import observation_for_agent, parse_ips_ids_incident

    raw = {
        **body.raw,
        "protocol": body.protocol,
        "event_type": body.event_type,
        "subscriber_id": body.subscriber_id,
        "session_id": body.session_id,
        "severity": body.severity,
    }
    bundle = parse_ips_ids_incident(
        raw,
        protocol=body.protocol,
        query=(body.query or "").strip(),
    )
    captured = bundle.get("capture") or {}
    if not captured:
        captured = {"agent_context": bundle.get("agent_context")}
    else:
        captured = {**captured, "ids_rule": bundle.get("ids_rule"), "blocked": bundle.get("blocked")}
    if not body.investigate:
        return captured
    question = (body.query or "").strip() or (
        "Why was this traffic blocked and what detection rule applies?"
        if bundle.get("blocked")
        else "Is this signalling behaviour consistent with a known attack or detection rule?"
    )
    agent = run_agent_graph(
        question,
        observation=observation_for_agent(bundle),
    )
    return {**captured, "investigation": agent, "detection_rules": bundle.get("detection_rules")}


@router.get("/events")
def get_network_events(protocol: str | None = None, subscriber_id: str | None = None, limit: int = 50):
    from app.realtime.event_ingestion import list_events

    return {"events": list_events(protocol=protocol, subscriber_id=subscriber_id, limit=limit)}


@router.post("/dictionary/expand")
def expand_query(body: ChatRequest):
    q = body.text()
    if not q:
        raise HTTPException(400, "Empty query")
    enhanced = get_query_enhancer().enhance(q)
    return {
        "original_query": enhanced.original_query,
        "enhanced_query": enhanced.enhanced_query,
        "expanded_terms": [
            {"term": t.term, "definition": t.definition, "domain": t.domain, "aliases": t.aliases}
            for t in enhanced.expanded_terms
        ],
    }


@router.get("/dictionary/{term}")
def get_dictionary_term(term: str):
    from app.nlp.domain_dictionary import find_term

    row = find_term(term)
    if not row:
        raise HTTPException(404, f"Term not found: {term}")
    return row


@router.get("/subscribers/{subscriber_id}")
def get_subscriber(subscriber_id: str):
    row = repo.find_subscriber(subscriber_id=subscriber_id)
    if not row:
        raise HTTPException(404, "Subscriber not found")
    return row


@router.get("/subscribers/{subscriber_id}/sessions")
def get_subscriber_sessions(subscriber_id: str):
    return {"sessions": repo.find_sessions(subscriber_id=subscriber_id)}


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    rows = repo.find_sessions(session_id=session_id)
    if not rows:
        raise HTTPException(404, "Session not found")
    return rows[0]


@router.get("/alerts")
def list_alerts(severity: str | None = None, protocol: str | None = None):
    return {"alerts": repo.find_alerts(severity=severity, protocol=protocol)}


@router.get("/attack-patterns")
def list_attack_patterns(protocol: str | None = None):
    return {"patterns": repo.find_attack_pattern(protocol=protocol)}


@router.post("/admin/init-db")
def admin_init_db():
    """Bootstrap PostgreSQL schema (dev only)."""
    init_schema()
    return {"ok": True, "postgres": postgres.backend_name()}


@router.post("/admin/seed-ontology")
def admin_seed_ontology(mirror: bool = True):
    """Create 16-table rows + optional Neo4j mirror (new_implementation_plan.md)."""
    init_schema()
    from app.ontology.seed import seed_ontology

    return seed_ontology(mirror_graph=mirror)


@router.post("/admin/feed-ir21-ontology")
def admin_feed_ir21_ontology(mirror: bool = True):
    """Project IR.21 SQL into plmn / roaming / diameter / message_policy (§8 Phase 1)."""
    init_schema()
    from app.ontology.ir21_etl import feed_from_ir21

    return feed_from_ir21(mirror_graph=mirror)


@router.post("/admin/compile-suricata")
def admin_compile_suricata(status: str | None = "PRODUCTION"):
    """Validate/format enrolled detection_rule Suricata text (§7)."""
    from app.ontology.suricata_compiler import compile_all

    rules = compile_all(status=status)
    return {"ok": True, "count": len(rules), "rules": rules}


@router.post("/admin/mirror-ontology")
def admin_mirror_ontology():
    """Re-run PostgreSQL → Neo4j ontology ETL."""
    from app.ontology.mirror import mirror_all

    return mirror_all()


@router.get("/ontology/status")
def ontology_status():
    from app.ontology.graph_store import get_ontology_store
    from app.ontology.taxonomy import load_taxonomy

    store = get_ontology_store()
    tax = load_taxonomy()
    counts = {}
    if postgres.is_available():
        for table in (
            "plmn", "network_element", "signaling_event", "attack_pattern", "detection_rule"
        ):
            try:
                row = postgres.fetch_one(f"SELECT count(*) AS n FROM {table}")
                counts[table] = int((row or {}).get("n") or 0)
            except Exception:
                counts[table] = -1
    return {
        "graph_backend": store.backend,
        "taxonomy": tax.get("name"),
        "taxonomy_version": tax.get("version"),
        "table_counts": counts,
    }