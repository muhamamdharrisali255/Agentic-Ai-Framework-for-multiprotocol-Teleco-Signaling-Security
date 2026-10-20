"""FastAPI backend for Signaling Firewall React UI."""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

os.environ.setdefault("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
os.environ.setdefault("CUDA_MPS_ACTIVE_THREAD_PERCENTAGE", "100")

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import config
from index_document import index_document
from shared.device import resolve_device
from shared.llm import answer_question, is_llm_available
from shared.index_report import build_index_report
from shared.retrieval import assemble_context, retrieve
from shared.vector_store import VectorStore

SAMPLE_PDF = config.SAMPLE_DOCS_DIR / "infrastructure_architecture.pdf"
UPLOAD_DIR = config.PROJECT_ROOT / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_QUESTIONS = [
    "What is a Category-1 signaling message?",
    "Which SS7 messages are prohibited on an international roaming interface?",
    "What is the difference between Category-2 and Category-3 signaling?",
    "What is the difference between Category-3.1 and Category-3.2?",
    "Which Diameter messages are normally associated with LTE authentication and location management?",
    "Which GTP-C messages are relevant to roaming session establishment?",
    "What parameters are used to validate an inbound roaming UpdateLocation?",
    "What parameters should be validated for a Diameter ULR?",
    "What parameters should be validated for a GTP Create Session Request?",
    "Why is MCC/MNC equality not sufficient for validating inbound roaming?",
]

K_SUITE = [
    {"id": "K01", "q": SAMPLE_QUESTIONS[0], "expect": "CAT1 definition"},
    {"id": "K02", "q": SAMPLE_QUESTIONS[1], "expect": "Prohibited SS7 messages"},
    {"id": "K03", "q": SAMPLE_QUESTIONS[2], "expect": "CAT2 vs CAT3"},
    {"id": "K04", "q": SAMPLE_QUESTIONS[3], "expect": "CAT3.1 vs 3.2"},
    {"id": "K05", "q": SAMPLE_QUESTIONS[4], "expect": "Diameter auth/location msgs"},
    {"id": "K06", "q": SAMPLE_QUESTIONS[5], "expect": "GTP-C session msgs"},
    {"id": "K07", "q": SAMPLE_QUESTIONS[6], "expect": "UpdateLocation params"},
    {"id": "K08", "q": SAMPLE_QUESTIONS[7], "expect": "Diameter ULR params"},
    {"id": "K09", "q": SAMPLE_QUESTIONS[8], "expect": "Create Session params"},
    {"id": "K10", "q": SAMPLE_QUESTIONS[9], "expect": "MCC/MNC vs partner check"},
]

FRONTEND_DIST = config.PROJECT_ROOT / "frontend" / "dist"

app = FastAPI(title="Signaling Firewall", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Agentic platform routes (dictionary, subscribers, alerts, agent debug)
try:
    from app.api.routes.platform import router as platform_router

    app.include_router(platform_router, prefix="/api", tags=["platform"])
except Exception as _plat_exc:
    print(f"[app] Platform routes not loaded: {_plat_exc}")

try:
    from app.api.routes.conversations import router as conversations_router

    app.include_router(conversations_router, prefix="/api", tags=["conversations"])
except Exception as _conv_exc:
    print(f"[app] Conversation routes not loaded: {_conv_exc}")

try:
    from app.api.routes.admin import router as admin_router

    app.include_router(admin_router, prefix="/api", tags=["admin"])
except Exception as _admin_exc:
    print(f"[app] Admin routes not loaded: {_admin_exc}")

# IDS/IPS Live Firewall routes
try:
    from app.api.routes.ids import router as ids_router

    app.include_router(ids_router, prefix="/api", tags=["ids"])
    print("[app] IDS routes loaded: /api/ids/*")
except Exception as _ids_exc:
    print(f"[app] IDS routes not loaded: {_ids_exc}")


@app.middleware("http")
async def log_requests(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        print(f"[http] {request.method} {request.url.path} → {response.status_code}")
    return response


class ChatRequest(BaseModel):
    message: str
    top_k: int = Field(default=5, ge=1, le=20)
    document: Optional[str] = None
    conversation_id: Optional[str] = None
    observation: Optional[dict[str, Any]] = None


def _pipeline_info(name: str) -> dict[str, Any]:
    store = VectorStore(name)
    docs = store.list_documents()
    return {"name": name, "chunks": store.chunk_count, "documents": docs}


def _hybrid_info() -> dict[str, Any]:
    """Structured knowledge store is GSMA RAEX IR.21 in PostgreSQL only."""
    try:
        from ir21.postgres import list_documents

        docs = list_documents()
        return {
            "enabled": True,
            "sql_backend": "postgresql",
            "structured": "ir21",
            "graph_backend": "off",
            "operators": [
                {
                    "tadig": d.get("tadig"),
                    "name": d.get("presentation_name") or d.get("organisation_name"),
                }
                for d in docs
            ],
            "structured_docs": [
                d.get("file_name") or d.get("document_id") for d in docs
            ],
        }
    except Exception as exc:
        return {"enabled": True, "sql_backend": "postgresql", "structured": "ir21", "error": str(exc)}


def _get_all_documents() -> list[str]:
    docs: set[str] = set()
    for p in ("original", "docling"):
        docs.update(VectorStore(p).list_documents())
    return sorted(docs)


def _hits_payload(hits) -> list[dict[str, Any]]:
    out = []
    for h in hits:
        c = h.chunk
        preview = c.content.replace("\n", " ").strip()
        if len(preview) > 280:
            preview = preview[:280] + "..."
        out.append(
            {
                "rank": h.rank,
                "score": round(float(h.score), 4),
                "chunk_id": c.chunk_id,
                "content_type": c.content_type.value,
                "page": c.page,
                "section": c.section,
                "toc_path": c.toc_path,
                "file_name": c.file_name,
                "table_id": c.table_id,
                "preview": preview,
            }
        )
    return out


def _retrieve_context(
    question: str,
    pipeline: str,
    top_k: int,
    document: str | None,
    search_query: str | None = None,
):
    sq = (search_query or question).strip() or question
    if config.HYBRID_RAG:
        from shared.hybrid_retrieval import hybrid_retrieve

        result = hybrid_retrieve(
            question, pipeline, top_k=top_k, document=document, search_query=sq
        )
        return result["hits"], result["context"], result["meta"]
    hits = retrieve(sq, pipeline, top_k=top_k, document=document)
    context = assemble_context(hits, pipeline)
    return hits, context, None


def _run_retrieval_only(
    question: str,
    pipeline: str,
    top_k: int,
    document: str | None,
    search_query: str | None = None,
):
    hits, context, meta = _retrieve_context(
        question, pipeline, top_k, document, search_query=search_query
    )
    vector_sources = [h.chunk.file_name for h in hits if h.chunk.file_name]
    fact_sources = list((meta or {}).get("fact_sources") or [])
    # Prefer structured-fact docs in the UI source line
    source_docs = list(dict.fromkeys([*fact_sources, *vector_sources]))
    return hits, context, source_docs, meta


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@app.get("/api/health")
def health():
    info = {"ok": True, "service": "signaling-firewall"}
    try:
        from app.config.settings import settings as platform_settings
        from app.database import postgres as pg

        info["agentic_rag"] = platform_settings.agentic_rag
        info["postgres"] = pg.backend_name()
    except Exception:
        pass
    return info


@app.get("/api/status")
def status():
    llm = "configured" if is_llm_available() else "not configured"
    try:
        from shared.llm import _load_local

        if is_llm_available() and _load_local.cache_info().currsize > 0:
            llm = "ready"
        elif is_llm_available():
            llm = "loading"
    except Exception:
        pass
    try:
        from app.config.settings import settings as platform_settings

        agentic_rag = platform_settings.agentic_rag
    except Exception:
        agentic_rag = True
    return {
        "pipelines": [_pipeline_info("original"), _pipeline_info("docling")],
        "hybrid": _hybrid_info(),
        "embedding_model": config.EMBEDDING_MODEL,
        "embedding_device": resolve_device(config.EMBEDDING_DEVICE),
        "llm": llm,
        "llm_model": config.LLM_MODEL_PATH or config.LLM_MODEL,
        "temperature": config.TEMPERATURE,
        "gemma": llm,
        "gemma_model": config.LLM_MODEL_PATH or config.LLM_MODEL,
        "top_k_default": config.TOP_K,
        "sample_questions": SAMPLE_QUESTIONS,
        "k_suite": K_SUITE,
        "documents": _get_all_documents(),
        "agentic_rag": agentic_rag,
    }


@app.get("/api/documents")
def documents():
    return {"documents": _get_all_documents()}


def _normalize_chat_request(req: ChatRequest) -> tuple[str, int, Optional[str], Optional[str]]:
    message = (req.message or "").strip()
    document = None if (not req.document or req.document == "All documents") else req.document
    top_k = int(req.top_k or config.TOP_K)
    conversation_id = (req.conversation_id or "").strip() or None
    return message, top_k, document, conversation_id


def _answer_both_pipelines(
    message: str,
    top_k: int,
    document: Optional[str],
    *,
    conversation_id: Optional[str] = None,
    history: list[dict[str, str]] | None = None,
    observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Retrieve + answer for both pipelines (agentic or legacy)."""
    try:
        from app.config.settings import settings as platform_settings
        from app.agent.graph import run_agent_graph

        if platform_settings.agentic_rag:
            agent = run_agent_graph(
                message,
                top_k=top_k,
                document=document,
                history=history,
                observation=observation,
            )
            chunks = agent.get("chunks") or []
            ms = agent.get("latency_ms", 0)
            agent_payload = {
                "pipeline": "agentic",
                "answer": agent["answer"],
                "ms": ms,
                "hits": len(chunks),
                "sources": agent.get("candidate_sources", []),
                "chunks": chunks,
                "hybrid": ",".join(agent.get("tools_used", [])),
                "query_type": agent.get("query_type", ""),
                "confidence": agent.get("confidence", ""),
                "tools_used": agent.get("tools_used", []),
                "stages": agent.get("stages", []),
                "finding": agent.get("finding") or {},
                "agent_context": agent.get("agent_context") or {},
                "round1_documents": agent.get("round1_documents") or [],
                "route": agent.get("route"),
                "specialists": agent.get("specialists") or [],
                "knowledge_kinds": agent.get("knowledge_kinds") or [],
                "detection_rules": agent.get("detection_rules") or [],
                "reports": agent.get("reports") or [],
            }
            return {
                "mode": "agentic",
                "search_query": agent.get("enhanced_query") or message,
                "hybrid": agent.get("query_type", ""),
                "agent": agent_payload,
            }
    except Exception as exc:
        print(f"[agent] fallback to legacy pipelines: {exc}")

    return _answer_both_pipelines_legacy(message, top_k, document)


def _answer_both_pipelines_legacy(message: str, top_k: int, document: Optional[str]) -> dict[str, Any]:
    """Legacy dual-pipeline path (facts-fast → Gemma retrieve)."""
    t_all = time.perf_counter()

    # Fast path: structured facts → formal table (no LLM, no rewrite)
    facts_answer = ""
    fact_sources: list[str] = []
    try:
        from shared.facts_answer import formal_brief_from_facts

        facts_answer, fact_sources, _ = formal_brief_from_facts(message, file_name=document)
    except Exception as exc:
        print(f"[ask] facts fast-path failed: {exc}")

    if facts_answer:
        ms = round((time.perf_counter() - t_all) * 1000)
        payload = {
            "pipeline": "docling",
            "answer": facts_answer,
            "ms": ms,
            "hits": 0,
            "sources": fact_sources,
            "chunks": [],
            "hybrid": "facts-fast",
            "pending_other": False,
        }
        orig = dict(payload)
        orig["pipeline"] = "original"
        print(f"[ask] facts-fast {ms}ms · sources={fact_sources}")
        return {
            "mode": "dual",
            "search_query": message,
            "hybrid": "facts-fast",
            "original": orig,
            "docling": payload,
        }

    # Slow path: vector retrieve + Gemma (may be slow on GPU)
    search_q = message
    try:
        from shared.llm import rewrite_query_for_search

        search_q = rewrite_query_for_search(message)
    except Exception:
        search_q = message

    orig_hits, orig_context, orig_sources, _ = _run_retrieval_only(
        message, "original", top_k, document, search_q
    )
    doc_hits, doc_context, doc_sources, doc_meta = _run_retrieval_only(
        message, "docling", top_k, document, search_q
    )

    hybrid_note = ""
    if doc_meta:
        from shared.hybrid_retrieval import hybrid_status_line

        hybrid_note = hybrid_status_line(doc_meta)

    t0 = time.perf_counter()
    try:
        orig_ans = answer_question(message, orig_context, style="professional")
    except Exception as exc:
        orig_ans = f"[Error: {exc}]"
    orig_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    try:
        doc_ans = answer_question(message, doc_context, style="professional")
    except Exception as exc:
        doc_ans = f"[Error: {exc}]"
    doc_ms = (time.perf_counter() - t0) * 1000

    return {
        "mode": "dual",
        "search_query": search_q,
        "hybrid": hybrid_note,
        "original": {
            "pipeline": "original",
            "answer": orig_ans,
            "ms": round(orig_ms),
            "hits": len(orig_hits),
            "sources": orig_sources,
            "chunks": _hits_payload(orig_hits[:12]),
            "pending_other": False,
        },
        "docling": {
            "pipeline": "docling",
            "answer": doc_ans,
            "ms": round(doc_ms),
            "hits": len(doc_hits),
            "sources": doc_sources,
            "chunks": _hits_payload(doc_hits[:12]),
            "hybrid": hybrid_note,
            "pending_other": False,
        },
    }


@app.post("/api/ask")
def ask(req: ChatRequest):
    """Non-streaming JSON Q&A (works through proxies that break SSE)."""
    message, top_k, document, conversation_id = _normalize_chat_request(req)
    if not message:
        return {"error": "Empty message"}
    try:
        from app.chat import conversations as conv

        history: list[dict[str, str]] = []
        if conversation_id:
            history = conv.history_for_agent(conversation_id)
        else:
            row = conv.create_conversation(
                title=message[:80],
                document_filter=document,
                top_k=top_k,
            )
            conversation_id = str(row["id"])

        conv.add_message(conversation_id, "user", message)

        result = _answer_both_pipelines(
            message,
            top_k,
            document,
            conversation_id=conversation_id,
            history=history,
            observation=req.observation,
        )
        result["conversation_id"] = conversation_id

        if result.get("mode") == "agentic" and result.get("agent"):
            agent = result["agent"]
            conv.add_message(
                conversation_id,
                "assistant",
                agent.get("answer", ""),
                metadata={"agent": agent, "mode": "agentic"},
            )
            if len(history) == 0:
                conv.touch_conversation(conversation_id, title=message[:80])
        elif result.get("original") and result.get("docling"):
            conv.add_message(
                conversation_id,
                "assistant",
                result["docling"].get("answer", ""),
                metadata={"mode": "dual", "original": result["original"], "docling": result["docling"]},
            )

        return result
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/chat")
def chat(req: ChatRequest):
    """SSE stream: status → token* → agent/original/docling → done."""
    import queue
    import threading

    message, top_k, document, conversation_id = _normalize_chat_request(req)
    if not message:
        return {"error": "Empty message"}

    def generate():
        from shared.llm import set_token_callback

        events: queue.Queue = queue.Queue()

        def on_token(text: str) -> None:
            events.put(("token", {"text": text}))

        def on_token_reset() -> None:
            events.put(("token_reset", {}))

        def worker() -> None:
            try:
                from app.chat import conversations as conv

                nonlocal_cid = conversation_id
                history: list[dict[str, str]] = []
                if nonlocal_cid:
                    history = conv.history_for_agent(nonlocal_cid)
                else:
                    row = conv.create_conversation(
                        title=message[:80],
                        document_filter=document,
                        top_k=top_k,
                    )
                    nonlocal_cid = str(row["id"])
                events.put(("conversation", {"conversation_id": nonlocal_cid}))
                conv.add_message(nonlocal_cid, "user", message)

                events.put(("status", {"stage": "retrieve", "text": "Retrieving ranked evidence…"}))
                set_token_callback(on_token, reset_cb=on_token_reset)
                try:
                    events.put(("status", {"stage": "generate", "text": "Generating answer…"}))
                    result = _answer_both_pipelines(
                        message,
                        top_k,
                        document,
                        conversation_id=nonlocal_cid,
                        history=history,
                        observation=req.observation,
                    )
                finally:
                    set_token_callback(None)

                if result.get("mode") == "agentic" and result.get("agent"):
                    agent = result["agent"]
                    conv.add_message(
                        nonlocal_cid,
                        "assistant",
                        agent.get("answer", ""),
                        metadata={"agent": agent, "mode": "agentic"},
                    )
                    events.put(("agent", agent))
                elif result.get("original") and result.get("docling"):
                    conv.add_message(
                        nonlocal_cid,
                        "assistant",
                        result["docling"].get("answer", ""),
                        metadata={
                            "mode": "dual",
                            "original": result["original"],
                            "docling": result["docling"],
                        },
                    )
                    events.put(("original", result["original"]))
                    events.put(("docling", result["docling"]))
                else:
                    events.put(("error", {"detail": "Incomplete agent response"}))
                events.put(("done", {"ok": True, "conversation_id": nonlocal_cid}))
            except Exception as exc:
                set_token_callback(None)
                events.put(("error", {"detail": str(exc)}))
                events.put(("done", {"ok": False}))

        threading.Thread(target=worker, daemon=True).start()
        while True:
            kind, payload = events.get()
            yield _sse(kind, payload)
            if kind == "done":
                break

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


def _index_path(path: Path, pipelines: list[str]) -> dict[str, Any]:
    selected = pipelines or ["original", "docling"]
    order = ["docling", "original"]
    selected = [p for p in order if p in selected] + [p for p in selected if p not in order]
    results = []
    for pipeline in selected:
        try:
            count, report = index_document(path, pipeline, force=True, return_report=True)
            results.append({"pipeline": pipeline, "ok": True, "chunks": count, "report": report})
        except Exception as exc:
            results.append({"pipeline": pipeline, "ok": False, "error": str(exc)})
    return {"file": path.name, "results": results}


@app.post("/api/index")
async def index_files(
    files: list[UploadFile] = File(...),
    pipelines: str = Form("original,docling"),
):
    pips = [p.strip() for p in pipelines.split(",") if p.strip()]
    saved: list[dict[str, Any]] = []
    for uf in files:
        suffix = Path(uf.filename or "upload.bin").suffix.lower()
        if suffix not in {".pdf", ".txt", ".md"}:
            saved.append({"file": uf.filename, "ok": False, "error": "Unsupported type"})
            continue
        dest = UPLOAD_DIR / f"{uuid.uuid4().hex}_{Path(uf.filename or 'doc').name}"
        with dest.open("wb") as out:
            shutil.copyfileobj(uf.file, out)
        saved.append(_index_path(dest, pips))
    return {"indexed": saved, "documents": _get_all_documents()}


@app.post("/api/index/sample")
def index_sample(pipelines: str = "original,docling"):
    if not SAMPLE_PDF.exists():
        return {"ok": False, "error": "Sample PDF not found"}
    pips = [p.strip() for p in pipelines.split(",") if p.strip()]
    result = _index_path(SAMPLE_PDF, pips)
    return {"ok": True, **result, "documents": _get_all_documents()}


@app.get("/api/structure")
def structure(document: Optional[str] = None):
    try:
        store = VectorStore("docling")
        if not store.chunks_path.exists():
            return {"documents": [], "report": None, "selected": None}
        store.load()
        names = sorted({c.file_name for c in (store._chunks or []) if c.file_name})
        selected = document if document in names else (names[-1] if names else None)
        if not selected:
            return {"documents": names, "report": None, "selected": None}
        chunks = [c for c in store._chunks if c.file_name == selected]
        report = build_index_report(chunks, "docling", selected)
        return {"documents": names, "selected": selected, "report": report}
    except Exception as exc:
        return {"documents": [], "selected": None, "report": None, "error": str(exc)}


# Serve React build if present
if FRONTEND_DIST.exists():
    assets = FRONTEND_DIST / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.api_route("/", methods=["GET", "HEAD"])
    def spa_root():
        return FileResponse(
            FRONTEND_DIST / "index.html",
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"])
    def spa(full_path: str):
        # Never shadow API routes (method mismatch would otherwise look like a bare 404)
        if full_path == "api" or full_path.startswith("api/"):
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail=f"API route not found: /{full_path}")
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.exists() and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(
            FRONTEND_DIST / "index.html",
            headers={"Cache-Control": "no-store, max-age=0"},
        )


def _warmup() -> None:
    def _bg_models():
        try:
            from shared.gpu_warmup import preload_gpu

            preload_gpu()
        except Exception as exc:
            print(f"[gpu] Model warmup failed: {exc}")

    threading.Thread(target=_bg_models, daemon=True).start()


def main() -> None:
    import uvicorn

    host = os.getenv("TE_HOST", os.getenv("HOST", "0.0.0.0"))
    port = int(os.getenv("PORT", os.getenv("GRADIO_PORT", "8000")))
    _warmup()
    print(f"[app] FastAPI + React on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
