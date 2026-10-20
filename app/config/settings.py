"""Platform settings — extends root config without breaking legacy imports."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import config as legacy


@dataclass
class Settings:
    project_root: Path = field(default_factory=lambda: legacy.PROJECT_ROOT)

    # LLM / embeddings
    embedding_model: str = legacy.EMBEDDING_MODEL
    embedding_device: str = legacy.EMBEDDING_DEVICE
    llm_model_path: str = legacy.LLM_MODEL_PATH
    llm_base_url: str = legacy.LLM_BASE_URL
    llm_model: str = legacy.LLM_MODEL
    temperature: float = legacy.TEMPERATURE
    retrieval_min_score: float = legacy.RETRIEVAL_MIN_SCORE
    retrieval_min_relevance: float = legacy.RETRIEVAL_MIN_RELEVANCE
    # Deprecated aliases
    gemma_model_path: str = legacy.LLM_MODEL_PATH
    gemma_base_url: str = legacy.LLM_BASE_URL

    # Vector stores
    vector_db_path: Path = legacy.VECTOR_DB_PATH
    qdrant_url: str = os.getenv("QDRANT_URL", "http://localhost:6333")
    qdrant_collection: str = os.getenv("QDRANT_COLLECTION", "telecom_chunks")
    use_qdrant: bool = os.getenv("USE_QDRANT", "true").lower() == "true"

    # PostgreSQL (telecom structured data)
    postgres_dsn: str = os.getenv(
        "POSTGRES_DSN",
        "postgresql://signaling:signaling@localhost:5432/signaling_rag",
    )

    # Agent pipeline
    agentic_rag: bool = os.getenv("AGENTIC_RAG", "true").lower() == "true"
    query_enhancement_max_expansions: int = int(os.getenv("QUERY_ENHANCEMENT_MAX_EXPANSIONS", "8"))
    candidate_selector_mode: str = os.getenv("CANDIDATE_SELECTOR_MODE", "metadata_filter")
    candidate_selector_max_sources: int = int(os.getenv("CANDIDATE_SELECTOR_MAX_SOURCES", "6"))
    candidate_selector_min_confidence: float = float(os.getenv("CANDIDATE_SELECTOR_MIN_CONFIDENCE", "0.35"))
    retrieval_top_k: int = legacy.TOP_K
    rerank_top_k: int = int(os.getenv("RERANK_TOP_K", "5"))
    rrf_k: int = legacy.RRF_K
    min_per_source: int = int(getattr(legacy, "MIN_PER_SOURCE", 2))
    sparse_identifier_boost: float = legacy.SPARSE_IDENTIFIER_BOOST
    use_cross_encoder: bool = legacy.USE_CROSS_ENCODER
    cross_encoder_model: str = legacy.CROSS_ENCODER_MODEL
    cross_encoder_device: str = getattr(legacy, "CROSS_ENCODER_DEVICE", "auto")
    cross_encoder_min_free_mb: float = float(
        getattr(legacy, "CROSS_ENCODER_MIN_FREE_MB", 1200)
    )
    cross_encoder_pool_k: int = legacy.CROSS_ENCODER_POOL_K
    cross_encoder_score_margin: float = legacy.CROSS_ENCODER_SCORE_MARGIN
    candidate_pool_k: int = legacy.CANDIDATE_POOL_K
    mmr_lambda: float = legacy.MMR_LAMBDA
    mmr_pool_k: int = legacy.MMR_POOL_K

    # Hybrid retrieval weights
    semantic_weight: float = float(os.getenv("SEMANTIC_WEIGHT", "0.7"))
    keyword_weight: float = float(os.getenv("KEYWORD_WEIGHT", "0.2"))
    metadata_weight: float = float(os.getenv("METADATA_WEIGHT", "0.1"))

    # Legacy hybrid (Mongo + Neo4j + FAISS)
    hybrid_rag: bool = legacy.HYBRID_RAG
    mongo_uri: str = legacy.MONGO_URI
    neo4j_uri: str = legacy.NEO4J_URI


settings = Settings()
