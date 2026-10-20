"""Chunk corpus store — chunks on disk, dense vectors in Qdrant (no FAISS)."""

from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import List, Optional

import config
from shared.schema import ChunkRecord, RetrievalResult


class VectorStore:
    """Pipeline-scoped chunk persistence; dense search is served by Qdrant."""

    def __init__(self, pipeline: str):
        self.pipeline = pipeline
        self.index_dir = config.VECTOR_DB_PATH / pipeline
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self._chunks: List[ChunkRecord] = []

    def _doc_dir(self, doc_name: str) -> Path:
        safe = doc_name.replace("/", "_").replace(" ", "_")
        return self.index_dir / "docs" / safe

    def _doc_chunks_path(self, doc_name: str) -> Path:
        return self._doc_dir(doc_name) / "chunks.pkl"

    def _doc_manifest_path(self, doc_name: str) -> Path:
        return self._doc_dir(doc_name) / "manifest.json"

    @property
    def chunks_path(self) -> Path:
        return self.index_dir / "chunks.pkl"

    @property
    def manifest_path(self) -> Path:
        return self.index_dir / "manifest.json"

    def build(self, chunks: List[ChunkRecord], force: bool = False) -> int:
        """Persist chunks and upsert vectors to Qdrant."""
        if not force and self.chunks_path.exists():
            self.load()
            return len(self._chunks)

        doc_name = chunks[0].file_name if chunks else "unknown"
        self._save_doc_chunks(doc_name, chunks)
        self._rebuild_combined_chunks()

        qdrant_points = 0
        try:
            from app.ingestion.qdrant_indexer import index_chunks_to_qdrant

            qdrant_points = index_chunks_to_qdrant(chunks, source=self.pipeline)
            if qdrant_points:
                print(f"[vector_store] Qdrant upserted {qdrant_points} chunks ({self.pipeline})")
        except Exception as exc:
            print(f"[vector_store] Qdrant upsert failed: {exc}")
            raise

        try:
            from shared.bm25_store import get_bm25_store
            from shared.tfidf_store import get_tfidf_store

            all_chunks = self._chunks or chunks
            get_bm25_store(self.pipeline).build(all_chunks)
            get_tfidf_store(self.pipeline).build(all_chunks)
        except Exception as exc:
            print(f"[lexical] warning: failed to build BM25/TF-IDF indexes: {exc}")
        return len(chunks)

    def _save_doc_chunks(self, doc_name: str, chunks: List[ChunkRecord]) -> None:
        d = self._doc_dir(doc_name)
        d.mkdir(parents=True, exist_ok=True)
        with open(self._doc_chunks_path(doc_name), "wb") as f:
            pickle.dump(chunks, f)
        manifest = {
            "pipeline": self.pipeline,
            "document": doc_name,
            "chunk_count": len(chunks),
            "embedding_model": config.EMBEDDING_MODEL,
            "vector_backend": "qdrant",
        }
        self._doc_manifest_path(doc_name).write_text(json.dumps(manifest, indent=2))

    def _rebuild_combined_chunks(self) -> None:
        all_chunks: List[ChunkRecord] = []
        docs_dir = self.index_dir / "docs"
        if docs_dir.exists():
            for doc_dir in sorted(docs_dir.iterdir()):
                cp = doc_dir / "chunks.pkl"
                if cp.exists():
                    with open(cp, "rb") as f:
                        all_chunks.extend(pickle.load(f))
        self._chunks = all_chunks
        if not all_chunks:
            return
        with open(self.chunks_path, "wb") as f:
            pickle.dump(all_chunks, f)
        manifest = {
            "pipeline": self.pipeline,
            "chunk_count": len(all_chunks),
            "documents": self.list_documents(),
            "embedding_model": config.EMBEDDING_MODEL,
            "vector_backend": "qdrant",
        }
        self.manifest_path.write_text(json.dumps(manifest, indent=2))

    def load(self) -> None:
        if not self.chunks_path.exists():
            raise FileNotFoundError(f"No chunk store for pipeline '{self.pipeline}'")
        with open(self.chunks_path, "rb") as f:
            self._chunks = pickle.load(f)

    def load_document(self, doc_name: str) -> List[ChunkRecord]:
        cp = self._doc_chunks_path(doc_name)
        if not cp.exists():
            return []
        with open(cp, "rb") as f:
            return pickle.load(f)

    def list_documents(self) -> List[str]:
        docs_dir = self.index_dir / "docs"
        if not docs_dir.exists():
            return []
        docs = []
        for d in sorted(docs_dir.iterdir()):
            if (d / "chunks.pkl").exists():
                manifest = d / "manifest.json"
                if manifest.exists():
                    data = json.loads(manifest.read_text())
                    docs.append(data.get("document", d.name))
                else:
                    docs.append(d.name)
        return docs

    def search(
        self,
        query: str,
        top_k: Optional[int] = None,
        document: Optional[str] = None,
    ) -> List[RetrievalResult]:
        """Dense search via Qdrant; maps hits back to local ChunkRecords."""
        from app.retrieval.qdrant_store import get_qdrant_store

        k = top_k or config.TOP_K
        qdrant = get_qdrant_store()
        if not qdrant.is_available():
            return []

        filters: dict = {"pipeline": self.pipeline}
        if document:
            filters["file_name"] = document

        hits = qdrant.search(query, top_k=k, filters=filters)
        if not hits and document:
            hits = qdrant.search(query, top_k=k, filters={"pipeline": self.pipeline})

        if not self._chunks and self.chunks_path.exists():
            self.load()
        by_id = {c.chunk_id: c for c in self._chunks}

        results: List[RetrievalResult] = []
        for rank, h in enumerate(hits, start=1):
            meta = h.get("metadata") or {}
            cid = str(h.get("chunk_id") or meta.get("chunk_id") or "")
            chunk = by_id.get(cid)
            if not chunk and meta.get("text"):
                chunk = ChunkRecord(
                    chunk_id=cid,
                    document_id=str(meta.get("document_id") or ""),
                    file_name=str(meta.get("file_name") or ""),
                    content=str(meta.get("text") or h.get("text") or ""),
                    pipeline=self.pipeline,
                    page=meta.get("page"),
                    section=str(meta.get("section") or ""),
                )
            if chunk:
                results.append(
                    RetrievalResult(chunk=chunk, score=float(h.get("score", 0)), rank=rank)
                )
        return results

    def get_by_id(self, chunk_id: str) -> Optional[ChunkRecord]:
        if not self._chunks and self.chunks_path.exists():
            self.load()
        for c in self._chunks:
            if c.chunk_id == chunk_id:
                return c
        return None

    def get_parent_chain(self, chunk: ChunkRecord) -> List[ChunkRecord]:
        if not self._chunks and self.chunks_path.exists():
            self.load()
        by_id = {c.chunk_id: c for c in self._chunks}
        chain: List[ChunkRecord] = []
        current = chunk
        depth = 0
        seen: set[str] = set()
        while current.parent_id and depth < config.CONTEXT_PARENT_DEPTH:
            if current.parent_id in seen:
                break
            seen.add(current.parent_id)
            parent = by_id.get(current.parent_id)
            if not parent:
                break
            chain.insert(0, parent)
            current = parent
            depth += 1
        return chain

    def get_neighbors(self, chunk: ChunkRecord) -> List[ChunkRecord]:
        if not self._chunks and self.chunks_path.exists():
            self.load()
        by_id = {c.chunk_id: c for c in self._chunks}
        out: List[ChunkRecord] = []
        if chunk.prev_chunk_id and chunk.prev_chunk_id in by_id:
            out.append(by_id[chunk.prev_chunk_id])
        if chunk.next_chunk_id and chunk.next_chunk_id in by_id:
            out.append(by_id[chunk.next_chunk_id])
        return out

    @property
    def chunk_count(self) -> int:
        if self._chunks:
            return len(self._chunks)
        if self.chunks_path.exists():
            with open(self.chunks_path, "rb") as f:
                return len(pickle.load(f))
        return 0
