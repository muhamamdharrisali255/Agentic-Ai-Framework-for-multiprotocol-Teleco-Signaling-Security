"""Post-fusion retrieval refinement: MMR diversity + optional cross-encoder rerank."""

from __future__ import annotations

from typing import Any

from app.config.settings import settings
from app.retrieval.cross_encoder import rerank_with_cross_encoder
from app.retrieval.mmr import maximal_marginal_relevance
from app.retrieval.query_terms import key_identifiers


def sparse_rrf_weight(query: str) -> float:
    """Boost BM25/TF-IDF contribution when the query has exact identifiers."""
    from app.retrieval.lexical_query import is_message_list_intent

    ids = key_identifiers(query)
    boost = float(settings.sparse_identifier_boost or 1.0)
    if ids:
        # More identifiers → stronger sparse leg (dense embeddings miss exact tokens).
        return boost + min(len(ids) * 0.25, 1.5)
    # NL "which messages…" questions are also sparse-heavy (command tables).
    if is_message_list_intent(query):
        return max(boost, 2.0)
    return 1.0


def refine_evidence(
    query: str,
    evidence: list[dict[str, Any]],
    *,
    top_k: int | None = None,
) -> list[dict[str, Any]]:
    """
    Apply MMR dedup then optional cross-encoder rerank on fused evidence.

    Input should be the wider fused pool (e.g. top-30); output is top_k for generation.
    """
    if not evidence:
        return []

    k = top_k or settings.rerank_top_k
    pool_k = max(k * 4, int(settings.cross_encoder_pool_k or 24))
    pool = sorted(evidence, key=lambda x: float(x.get("score") or 0), reverse=True)[:pool_k]

    mmr_k = max(k * 2, int(settings.mmr_pool_k or 16))
    diversified = maximal_marginal_relevance(
        pool,
        top_k=min(mmr_k, len(pool)),
        lambda_mult=float(settings.mmr_lambda or 0.7),
    )

    if settings.use_cross_encoder and diversified:
        try:
            return rerank_with_cross_encoder(
                query,
                diversified,
                model_name=settings.cross_encoder_model,
                top_k=k,
            )
        except Exception as exc:
            print(f"[retrieval] cross-encoder rerank skipped: {exc}")

    return diversified[:k]
