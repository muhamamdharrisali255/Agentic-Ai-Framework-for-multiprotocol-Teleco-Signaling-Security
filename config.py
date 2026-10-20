"""Central configuration for the Docling vs Original embedding experiment."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")


def _env_first(*keys: str, default: str = "") -> str:
    for key in keys:
        val = os.getenv(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return default


def _env_bool(*keys: str, default: bool = False) -> bool:
    raw = _env_first(*keys, default="")
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes")


# Shared telecom Qwen chatbot (1.5B) — same weights for embed + generate.
_TELECOM_QWEN_HUB = "ligaments-dev/Qwen-telecom-chatbot-model"
_DEFAULT_LLM = PROJECT_ROOT / "models" / "Qwen2.5-14B-Instruct"
_DEFAULT_GEMMA = _DEFAULT_LLM

DOCUMENT_PIPELINE: str = os.getenv("DOCUMENT_PIPELINE", "original")
_OTEL_EMBED_HUB = "farbodtavakkoli/OTel-Embedding-300M"
_OTEL_RERANK_HUB = "farbodtavakkoli/OTel-Reranker-0.6B"
_OTEL_LLM_HUB = "farbodtavakkoli/OTel-LLM-E4B-IT"
_OTEL_EMBED_LOCAL = PROJECT_ROOT / "models" / "OTel-Embedding-300M"
_OTEL_RERANK_LOCAL = PROJECT_ROOT / "models" / "OTel-Reranker-0.6B"
_OTEL_LLM_LOCAL = PROJECT_ROOT / "models" / "OTel-LLM-E4B-IT"

_QWEN_LLM_LOCAL = PROJECT_ROOT / "models" / "Qwen2.5-14B-Instruct"
_QWEN_EMBED_LOCAL = PROJECT_ROOT / "models" / "Qwen3-Embedding-0.6B"
_QWEN_EMBED_HUB = "Qwen/Qwen3-Embedding-0.6B"
_TELECOM_QWEN_LOCAL = PROJECT_ROOT / "models" / "Qwen-telecom-chatbot-model"


def _default_embedding_model() -> str:
    if _TELECOM_QWEN_LOCAL.joinpath("config.json").exists():
        return str(_TELECOM_QWEN_LOCAL)
    if _OTEL_EMBED_LOCAL.joinpath("config.json").exists():
        return str(_OTEL_EMBED_LOCAL)
    if _QWEN_EMBED_LOCAL.joinpath("config.json").exists():
        return str(_QWEN_EMBED_LOCAL)
    return _TELECOM_QWEN_HUB


EMBEDDING_MODEL: str = _env_first("EMBEDDING_MODEL", default=_default_embedding_model())
EMBEDDING_DEVICE: str = os.getenv("EMBEDDING_DEVICE", "cuda")
EMBEDDING_BATCH_SIZE: int = int(os.getenv("EMBEDDING_BATCH_SIZE", "512"))
# When true, index TOC/heading/short chunks so full Docling docs land in Qdrant.
INDEX_ALL_DOCLING_CHUNKS: bool = _env_bool("INDEX_ALL_DOCLING_CHUNKS", default=True)
EMBEDDING_MAX_LENGTH: int = int(os.getenv("EMBEDDING_MAX_LENGTH", "2048"))
DOCLING_LAYOUT_BATCH_SIZE: int = int(os.getenv("DOCLING_LAYOUT_BATCH_SIZE", "8"))
DOCLING_OCR_BATCH_SIZE: int = int(os.getenv("DOCLING_OCR_BATCH_SIZE", "8"))
DOCLING_TABLE_BATCH_SIZE: int = int(os.getenv("DOCLING_TABLE_BATCH_SIZE", "8"))
DOCLING_NUM_THREADS: int = int(os.getenv("DOCLING_NUM_THREADS", "16"))

MAX_NEW_TOKENS: int = int(os.getenv("MAX_NEW_TOKENS", "1024"))
LLM_MAX_INPUT_TOKENS: int = int(os.getenv("LLM_MAX_INPUT_TOKENS", "8192"))
TEMPERATURE: float = float(os.getenv("TEMPERATURE", "0.15"))

DOCUMENT_PIPELINE: str = os.getenv("DOCUMENT_PIPELINE", "original")
# Instruction LLM — shared telecom Qwen by default
# ---------------------------------------------------------------------------
_DEFAULT_LLM_PATH = (
    _TELECOM_QWEN_LOCAL
    if _TELECOM_QWEN_LOCAL.joinpath("config.json").exists()
    else (_OTEL_LLM_LOCAL if _OTEL_LLM_LOCAL.joinpath("config.json").exists() else _DEFAULT_LLM)
)

LLM_MODEL: str = _env_first(
    "LLM_MODEL",
    "GEMMA_MODEL",
    default=_TELECOM_QWEN_HUB,
)
LLM_MODEL_PATH: str = _env_first(
    "LLM_MODEL_PATH",
    "GEMMA_MODEL_PATH",
    default=str(_DEFAULT_LLM_PATH) if Path(_DEFAULT_LLM_PATH).joinpath("config.json").exists() else "",
)
LLM_USE_LOCAL: bool = _env_bool(
    "LLM_USE_LOCAL",
    "GEMMA_USE_LOCAL",
    default=bool(LLM_MODEL_PATH or LLM_MODEL),
)
LLM_BASE_URL: str = _env_first("LLM_BASE_URL", "GEMMA_BASE_URL", default="").rstrip("/")
_OTEL_LLM = "otel" in (LLM_MODEL + LLM_MODEL_PATH).lower()
# 1.5B telecom Qwen fits bf16; large Qwen/OTel may need 4-bit.
_SMALL_QWEN = "1.5b" in (LLM_MODEL + LLM_MODEL_PATH).lower() or "telecom-chatbot" in (
    LLM_MODEL + LLM_MODEL_PATH
).lower()
LLM_LOAD_IN_4BIT: bool = _env_bool(
    "LLM_LOAD_IN_4BIT",
    "GEMMA_LOAD_IN_4BIT",
    default=not (_OTEL_LLM or _SMALL_QWEN),
)
LLM_PRELOAD: bool = _env_bool("LLM_PRELOAD", "GEMMA_PRELOAD", default=True)

DOCLING_PRELOAD: bool = os.getenv("DOCLING_PRELOAD", "true").lower() == "true"

# Retrieval strictness (higher = fewer, more relevant vector hits)
RETRIEVAL_MIN_SCORE: float = float(os.getenv("RETRIEVAL_MIN_SCORE", "0.35"))
RETRIEVAL_MIN_RELEVANCE: float = float(os.getenv("RETRIEVAL_MIN_RELEVANCE", "0.5"))
USE_QDRANT: bool = _env_bool("USE_QDRANT", default=True)

# Hybrid fusion tuning
RRF_K: int = int(os.getenv("RRF_K", "60"))
MIN_PER_SOURCE: int = int(os.getenv("MIN_PER_SOURCE", "2"))
SPARSE_IDENTIFIER_BOOST: float = float(os.getenv("SPARSE_IDENTIFIER_BOOST", "2.0"))
USE_CROSS_ENCODER: bool = _env_bool("USE_CROSS_ENCODER", default=False)
CROSS_ENCODER_MODEL: str = _env_first(
    "CROSS_ENCODER_MODEL",
    default=str(_OTEL_RERANK_LOCAL)
    if _OTEL_RERANK_LOCAL.joinpath("config.json").exists()
    else "cross-encoder/ms-marco-MiniLM-L-6-v2",
)
# auto = CUDA when enough free VRAM, else CPU (needed when 14B LLM holds the GPU).
CROSS_ENCODER_DEVICE: str = os.getenv("CROSS_ENCODER_DEVICE", "auto").strip().lower()
CROSS_ENCODER_MIN_FREE_MB: float = float(os.getenv("CROSS_ENCODER_MIN_FREE_MB", "1200"))
CROSS_ENCODER_POOL_K: int = int(os.getenv("CROSS_ENCODER_POOL_K", "40"))
# Keep CE hits within this score distance of the best hit (drops weak bleed).
CROSS_ENCODER_SCORE_MARGIN: float = float(os.getenv("CROSS_ENCODER_SCORE_MARGIN", "2.0"))
# BM25+dense RRF candidate pool size before cross-encoder (diagram: Top-30).
CANDIDATE_POOL_K: int = int(os.getenv("CANDIDATE_POOL_K", "30"))
MMR_LAMBDA: float = float(os.getenv("MMR_LAMBDA", "0.7"))
MMR_POOL_K: int = int(os.getenv("MMR_POOL_K", "12"))

# Deprecated aliases — prefer LLM_* env vars and shared.llm imports
GEMMA_PRELOAD = LLM_PRELOAD
GEMMA_BASE_URL = LLM_BASE_URL
GEMMA_MODEL = LLM_MODEL
GEMMA_MODEL_PATH = LLM_MODEL_PATH
GEMMA_USE_LOCAL = LLM_USE_LOCAL
GEMMA_LOAD_IN_4BIT = LLM_LOAD_IN_4BIT

VECTOR_DB_PATH: Path = Path(os.getenv("VECTOR_DB_PATH", str(PROJECT_ROOT / ".vector_cache")))

ORIGINAL_CHUNK_SIZE: int = int(os.getenv("ORIGINAL_CHUNK_SIZE", "512"))
ORIGINAL_CHUNK_OVERLAP: int = int(os.getenv("ORIGINAL_CHUNK_OVERLAP", "64"))
DOCLING_MAX_CHUNK_CHARS: int = int(os.getenv("DOCLING_MAX_CHUNK_CHARS", "800"))

TOP_K: int = int(os.getenv("TOP_K", "5"))
CONTEXT_PARENT_DEPTH: int = int(os.getenv("CONTEXT_PARENT_DEPTH", "3"))
CONTEXT_PREV_CHUNKS: int = int(os.getenv("CONTEXT_PREV_CHUNKS", "1"))
CONTEXT_NEXT_CHUNKS: int = int(os.getenv("CONTEXT_NEXT_CHUNKS", "1"))
# ~3–4 chars/token; keep below LLM_MAX_INPUT_TOKENS after chat template overhead.
CONTEXT_MAX_CHARS: int = int(os.getenv("CONTEXT_MAX_CHARS", "48000"))
MAX_RETRIEVAL_CONTEXT_CHARS: int = int(
    os.getenv("MAX_RETRIEVAL_CONTEXT_CHARS", str(CONTEXT_MAX_CHARS))
)
QDRANT_UPSERT_BATCH_SIZE: int = int(os.getenv("QDRANT_UPSERT_BATCH_SIZE", "64"))
# Alias for collection name — primary source remains QDRANT_COLLECTION / settings.
DOCLING_QDRANT_COLLECTION: str = os.getenv(
    "DOCLING_QDRANT_COLLECTION",
    os.getenv("QDRANT_COLLECTION", "telecom_chunks"),
)

_DEFAULT_ENTITIES = (
    "IP_ADDRESS,PORT,HOSTNAME,URL,DATE,TADIG,MCC,MNC,IMSI_RANGE,MSISDN_RANGE,"
    "GT,REALM,SECTION_ID,NODE_TYPE,PROTOCOL,QOS_PROFILE,IDENTIFIER,"
    "PERSON,ORGANIZATION,LOCATION,SERVICE,SERVER,VM,DATABASE,PROJECT"
)
ENTITY_TYPES: list[str] = [
    e.strip() for e in os.getenv("ENTITY_TYPES", _DEFAULT_ENTITIES).split(",") if e.strip()
]

EVALUATION_DIR: Path = Path(os.getenv("EVALUATION_DIR", str(PROJECT_ROOT / "evaluation")))
CANONICAL_DIR: Path = PROJECT_ROOT / "data" / "canonical"
SAMPLE_DOCS_DIR: Path = PROJECT_ROOT / "sample_documents"

# Structured store for RAEX IR.21 records. IR.21 is a filled-in template, so it
# is parsed into relations and queried with SQL instead of being embedded.
POSTGRES_DSN: str = os.getenv(
    "POSTGRES_DSN",
    "postgresql://signaling:signaling@localhost:5432/signaling_rag",
)

# Hybrid RAG stores (MongoDB structured facts + Neo4j graph)
MONGO_URI: str = os.getenv(
    "MONGO_URI",
    "mongodb://signaling:signaling@localhost:27017/signaling_rag?authSource=admin",
)
MONGO_DB: str = os.getenv("MONGO_DB", "signaling_rag")
MONGO_AI_EXTRACT: bool = os.getenv("MONGO_AI_EXTRACT", "true").lower() == "true"
VOYAGE_API_KEY: str = os.getenv("VOYAGE_API_KEY", "")
VOYAGE_EMBED_MODEL: str = os.getenv("VOYAGE_EMBED_MODEL", "voyage-3.5-lite")
STRUCTURED_DB_PATH: Path = Path(
    os.getenv("STRUCTURED_DB_PATH", str(PROJECT_ROOT / "data" / "structured" / "ir21.sqlite"))
)
# The entity graph is a future extension, not part of the retrieval path: no
# query route reads from it, so indexing into it only slows enrollment down.
ENABLE_GRAPH_LAYER: bool = os.getenv("ENABLE_GRAPH_LAYER", "false").lower() == "true"
NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "signaling123")
GRAPH_JSON_PATH: Path = Path(
    os.getenv("GRAPH_JSON_PATH", str(PROJECT_ROOT / "data" / "graph" / "entities.json"))
)
HYBRID_RAG: bool = os.getenv("HYBRID_RAG", "true").lower() == "true"
