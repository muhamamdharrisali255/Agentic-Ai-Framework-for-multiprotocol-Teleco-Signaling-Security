"""Embedding provider abstraction (implementation_plan.md §11)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Protocol

from app.config.settings import settings


class EmbeddingProvider(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        ...

    def embed_query(self, query: str) -> list[float]:
        ...

    @property
    def dimension(self) -> int:
        ...


class SentenceTransformerProvider:
    """Local sentence-transformers backend (default)."""

    def __init__(self, model_name: str | None = None, device: str | None = None) -> None:
        from shared.embeddings import get_embedding_model

        self._model = get_embedding_model()
        self._model_name = model_name or settings.embedding_model
        self._device = device or settings.embedding_device
        self._dim: int | None = None

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        from shared.embeddings import embed_texts

        vecs = embed_texts(texts)
        return [v.tolist() for v in vecs]

    def embed_query(self, query: str) -> list[float]:
        from shared.embeddings import embed_query

        return embed_query(query).tolist()

    @property
    def dimension(self) -> int:
        if self._dim is None:
            self._dim = len(self.embed_query("probe"))
        return self._dim


@lru_cache(maxsize=1)
def get_embedding_provider() -> EmbeddingProvider:
    return SentenceTransformerProvider()
