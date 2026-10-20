"""Trained candidate router — Phase 9 interface (falls back to metadata filter)."""

from __future__ import annotations

from app.config.settings import settings
from app.nlp.query_enhancer import EnhancedQuery
from app.retrieval.candidate_selector import CandidateFilter, CandidateSourceSelector


class TrainedCandidateRouter:
    """Drop-in replacement for CandidateSourceSelector when a model is trained.

    POC: delegates to metadata_filter baseline. Set CANDIDATE_SELECTOR_MODE=trained_router
    to route through this class (still uses fallback until a model is loaded).
    """

    fallback: CandidateSourceSelector

    def __init__(self) -> None:
        self.fallback = CandidateSourceSelector()
        self._model_loaded = False

    def select(
        self,
        enhanced: EnhancedQuery,
        query_type: str,
        entities: dict | None = None,
    ) -> CandidateFilter:
        if settings.candidate_selector_mode == "trained_router" and self._model_loaded:
            # Future: run sklearn/onnx model here
            pass
        return self.fallback.select(enhanced, query_type, entities or {})


def get_router():
    if settings.candidate_selector_mode == "trained_router":
        return TrainedCandidateRouter()
    return CandidateSourceSelector()
