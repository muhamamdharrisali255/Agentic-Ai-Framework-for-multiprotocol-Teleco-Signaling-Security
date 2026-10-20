"""TF-IDF lexical retrieval over chunk corpora (complements dense FAISS vectors)."""

from __future__ import annotations

import pickle
import re
from pathlib import Path
from typing import List, Optional

import config
from shared.schema import ChunkRecord, RetrievalResult


def _tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) >= 2]


def _chunk_text(chunk: ChunkRecord) -> str:
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
        for row in chunk.structured_table.rows or []:
            if isinstance(row, dict):
                parts.extend(f"{k} {v}" for k, v in row.items())
    return "\n".join(str(p) for p in parts if p)


class TfidfStore:
    """Pipeline-scoped TF-IDF index built from the same chunks as FAISS."""

    def __init__(self, pipeline: str):
        self.pipeline = pipeline
        self.index_dir = config.VECTOR_DB_PATH / pipeline
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self._vectorizer = None
        self._matrix = None
        self._chunks: List[ChunkRecord] = []

    @property
    def path(self) -> Path:
        return self.index_dir / "tfidf.pkl"

    def build(self, chunks: List[ChunkRecord]) -> int:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self._chunks = list(chunks)
        corpus = [_chunk_text(c) for c in self._chunks]
        self._vectorizer = TfidfVectorizer(
            tokenizer=_tokenize,
            token_pattern=None,
            lowercase=True,
            sublinear_tf=True,
            max_df=0.92,
            min_df=1,
            ngram_range=(1, 2),
        )
        self._matrix = self._vectorizer.fit_transform(corpus)
        with open(self.path, "wb") as f:
            pickle.dump(
                {
                    "chunks": self._chunks,
                    "vectorizer": self._vectorizer,
                    "matrix": self._matrix,
                },
                f,
            )
        return len(self._chunks)

    def load(self) -> None:
        if not self.path.exists():
            chunks_path = self.index_dir / "chunks.pkl"
            if chunks_path.exists():
                with open(chunks_path, "rb") as f:
                    chunks = pickle.load(f)
                self.build(chunks)
            return
        with open(self.path, "rb") as f:
            data = pickle.load(f)
        self._chunks = data.get("chunks") or []
        self._vectorizer = data.get("vectorizer")
        self._matrix = data.get("matrix")

    def ensure_ready(self, chunks: Optional[List[ChunkRecord]] = None) -> None:
        if self._vectorizer is not None and self._chunks:
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
        if self._vectorizer is None or self._matrix is None or not self._chunks:
            return []

        q_vec = self._vectorizer.transform([query])
        scores = (self._matrix @ q_vec.T).toarray().ravel()

        candidates: list[tuple[int, float]] = []
        for i, score in enumerate(scores):
            if score <= 0:
                continue
            chunk = self._chunks[i]
            if document and chunk.file_name != document:
                continue
            candidates.append((i, float(score)))
        candidates.sort(key=lambda x: x[1], reverse=True)

        results: List[RetrievalResult] = []
        for rank, (i, score) in enumerate(candidates[:top_k], start=1):
            results.append(RetrievalResult(chunk=self._chunks[i], score=score, rank=rank))
        return results


_stores: dict[str, TfidfStore] = {}


def get_tfidf_store(pipeline: str) -> TfidfStore:
    if pipeline not in _stores:
        _stores[pipeline] = TfidfStore(pipeline)
    return _stores[pipeline]
