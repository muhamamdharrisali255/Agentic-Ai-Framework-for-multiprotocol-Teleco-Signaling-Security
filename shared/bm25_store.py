"""BM25 lexical retrieval over chunk corpora."""

from __future__ import annotations

import pickle
import re
from pathlib import Path
from typing import List, Optional

from rank_bm25 import BM25Okapi

import config
from shared.schema import ChunkRecord, RetrievalResult


def _tokenize(text: str) -> list[str]:
    """Lexical tokens for BM25.

    Also indexes hyphenated compounds (``GTP-C`` → ``gtpc``) so control/user-plane
    markers survive after the hyphen is stripped by the alphanumeric splitter.
    """
    low = (text or "").lower()
    toks = [t for t in re.findall(r"[a-z0-9]+", low) if len(t) >= 2]
    for compound in re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)+", low):
        compact = compound.replace("-", "")
        if len(compact) >= 2:
            toks.append(compact)
    return toks


def _chunk_text(chunk: ChunkRecord) -> str:
    """Text used for BM25 — content plus light metadata for lexical recall."""
    parts = [
        chunk.content or "",
        chunk.section or "",
        chunk.subsection or "",
        chunk.toc_path or "",
        chunk.file_name or "",
        chunk.content_type.value if chunk.content_type else "",
    ]
    if chunk.structured_table:
        parts.extend(chunk.structured_table.headers or [])
        # Every row must be lexically searchable; a cap here silently hides
        # values that exist in the document.
        for row in chunk.structured_table.rows or []:
            if isinstance(row, dict):
                parts.extend(f"{k} {v}" for k, v in row.items())
    return "\n".join(str(p) for p in parts if p)


class BM25Store:
    """Pipeline-scoped BM25 index built from the same chunks as FAISS."""

    def __init__(self, pipeline: str):
        self.pipeline = pipeline
        self.index_dir = config.VECTOR_DB_PATH / pipeline
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self._bm25: Optional[BM25Okapi] = None
        self._chunks: List[ChunkRecord] = []
        self._tokenized: List[List[str]] = []

    @property
    def path(self) -> Path:
        return self.index_dir / "bm25.pkl"

    def build(self, chunks: List[ChunkRecord]) -> int:
        self._chunks = list(chunks)
        self._tokenized = [_tokenize(_chunk_text(c)) for c in self._chunks]
        self._bm25 = BM25Okapi(self._tokenized) if self._tokenized else None
        with open(self.path, "wb") as f:
            pickle.dump({"chunks": self._chunks, "tokenized": self._tokenized}, f)
        return len(self._chunks)

    def load(self) -> None:
        if not self.path.exists():
            # Fall back: rebuild from FAISS chunk pickle if present
            chunks_path = self.index_dir / "chunks.pkl"
            if chunks_path.exists():
                with open(chunks_path, "rb") as f:
                    chunks = pickle.load(f)
                self.build(chunks)
            return
        with open(self.path, "rb") as f:
            data = pickle.load(f)
        self._chunks = data.get("chunks") or []
        self._tokenized = data.get("tokenized") or [_tokenize(c.content) for c in self._chunks]
        self._bm25 = BM25Okapi(self._tokenized) if self._tokenized else None

    def ensure_ready(self, chunks: Optional[List[ChunkRecord]] = None) -> None:
        if self._bm25 is not None and self._chunks:
            return
        if self.path.exists():
            self.load()
        elif chunks:
            self.build(chunks)
        else:
            self.load()

    def search(
        self,
        query: str,
        top_k: int = 5,
        document: Optional[str] = None,
    ) -> List[RetrievalResult]:
        self.ensure_ready()
        if not self._bm25 or not self._chunks:
            return []

        tokens = _tokenize(query)
        if not tokens:
            return []

        scores = self._bm25.get_scores(tokens)
        # Optional document filter
        candidates = []
        for i, score in enumerate(scores):
            chunk = self._chunks[i]
            if document and chunk.file_name != document:
                continue
            if score <= 0:
                continue
            candidates.append((i, float(score)))
        candidates.sort(key=lambda x: x[1], reverse=True)
        results: List[RetrievalResult] = []
        for rank, (i, score) in enumerate(candidates[:top_k], start=1):
            results.append(RetrievalResult(chunk=self._chunks[i], score=score, rank=rank))
        return results


_stores: dict[str, BM25Store] = {}


def get_bm25_store(pipeline: str) -> BM25Store:
    if pipeline not in _stores:
        _stores[pipeline] = BM25Store(pipeline)
    return _stores[pipeline]


def reciprocal_rank_fusion(
    result_lists: List[List[RetrievalResult]],
    k: int = 60,
    top_k: int = 10,
    list_weights: list[float] | None = None,
) -> List[RetrievalResult]:
    """Fuse ranked lists with RRF. Higher fused score is better."""
    fused: dict[str, dict] = {}
    weights = list_weights or [1.0] * len(result_lists)
    for list_idx, results in enumerate(result_lists):
        weight = weights[list_idx] if list_idx < len(weights) else 1.0
        for r in results:
            key = f"{r.chunk.document_id or r.chunk.file_name}||{r.chunk.chunk_id}"
            if key not in fused:
                fused[key] = {"chunk": r.chunk, "score": 0.0}
            fused[key]["score"] += weight * (1.0 / (k + r.rank))

    ordered = sorted(fused.values(), key=lambda x: x["score"], reverse=True)[:top_k]
    out: List[RetrievalResult] = []
    for i, item in enumerate(ordered, start=1):
        out.append(RetrievalResult(chunk=item["chunk"], score=float(item["score"]), rank=i))
    return out
