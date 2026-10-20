"""Qdrant vector store (implementation_plan.md §12)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import config
from app.config.settings import settings
from app.ingestion.embeddings import get_embedding_provider

# Payload fields indexed for filter/search (KEYWORD unless noted).
PAYLOAD_INDEX_FIELDS: tuple[tuple[str, str], ...] = (
    ("pipeline", "keyword"),
    ("file_name", "keyword"),
    ("knowledge_kind", "keyword"),
    ("document_id", "keyword"),
    ("chunk_id", "keyword"),
    ("source", "keyword"),
    ("protocol", "keyword"),
    ("content_type", "keyword"),
    ("domain", "keyword"),
    ("document_type", "keyword"),
    ("series", "keyword"),
    ("tadig", "keyword"),
    ("table_id", "keyword"),
    ("parent_id", "keyword"),
    ("embedding_model", "keyword"),
)


class QdrantVectorStore:
    def __init__(self) -> None:
        self._client: Any = None
        # Prefer DOCLING_QDRANT_COLLECTION when set; else platform QDRANT_COLLECTION.
        self._collection = (
            getattr(config, "DOCLING_QDRANT_COLLECTION", None)
            or settings.qdrant_collection
        )
        self._embedder = get_embedding_provider()

    def _get_client(self):
        if self._client is not None:
            return self._client
        from qdrant_client import QdrantClient

        self._client = QdrantClient(url=settings.qdrant_url, timeout=300, check_compatibility=False)
        return self._client

    def is_available(self) -> bool:
        try:
            self._get_client().get_collections()
            return True
        except Exception:
            return False

    def ensure_payload_indexes(self) -> None:
        from qdrant_client.models import PayloadSchemaType

        client = self._get_client()
        if not client.collection_exists(self._collection):
            return
        schema_map = {
            "keyword": PayloadSchemaType.KEYWORD,
            "integer": PayloadSchemaType.INTEGER,
            "float": PayloadSchemaType.FLOAT,
            "bool": PayloadSchemaType.BOOL,
        }
        for field, kind in PAYLOAD_INDEX_FIELDS:
            try:
                client.create_payload_index(
                    collection_name=self._collection,
                    field_name=field,
                    field_schema=schema_map[kind],
                )
            except Exception:
                pass

    def create_collection(self, recreate: bool = False) -> None:
        from qdrant_client.models import Distance, VectorParams

        client = self._get_client()
        dim = self._embedder.dimension
        if recreate and client.collection_exists(self._collection):
            client.delete_collection(self._collection)
        if not client.collection_exists(self._collection):
            client.create_collection(
                collection_name=self._collection,
                vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
            )
        self.ensure_payload_indexes()

    def upsert_chunks(self, chunks: list[dict[str, Any]], *, ensure_collection: bool = True) -> int:
        if not chunks:
            return 0
        from qdrant_client.models import PointStruct

        client = self._get_client()
        if ensure_collection:
            self.create_collection()
        from app.ingestion.embed_text import clean_text_for_embedding, is_indexable_passage

        # Embed clean section body only — strip Document/ToC-path boilerplate.
        cleaned: list[str] = []
        keep_chunks: list[dict[str, Any]] = []
        for c in chunks:
            text = clean_text_for_embedding(
                str(c.get("text") or ""),
                section=str(c.get("section") or "") or None,
            )
            if not is_indexable_passage(
                text,
                section=str(c.get("section") or "") or None,
                content_type=str(c.get("content_type") or "") or None,
            ):
                continue
            cleaned.append(text)
            keep_chunks.append(c)
        if not keep_chunks:
            return 0
        chunks = keep_chunks
        vectors = self._embedder.embed_documents(cleaned)
        embed_model = config.EMBEDDING_MODEL
        embed_dim = int(self._embedder.dimension)
        vectors = [
            self._sanitize_vector(v, chunk_id=str(c.get("chunk_id") or i), dim=embed_dim)
            for i, (c, v) in enumerate(zip(chunks, vectors))
        ]
        now = datetime.now(timezone.utc).isoformat()
        points = []
        for chunk, vec, clean in zip(chunks, vectors, cleaned):
            if vec is None:
                # Should not happen after sanitize fallback — keep guard for safety.
                print(
                    f"[qdrant] skip chunk {chunk.get('chunk_id')}: invalid embedding vector",
                    flush=True,
                )
                continue
            cid = chunk.get("chunk_id") or str(uuid.uuid4())
            document_id = str(chunk.get("document_id") or chunk.get("file_name") or "")
            pipeline = str(chunk.get("pipeline") or "")
            point_id = self._point_id(cid, document_id=document_id, pipeline=pipeline)
            payload = {**chunk, "chunk_id": cid}
            # Persist cleaned text so retrieval evidence matches what was embedded.
            if clean:
                payload["text"] = clean
            payload.setdefault("created_at", now)
            payload.setdefault("indexed_at", now)
            payload.setdefault("embedding_model", embed_model)
            payload.setdefault("embedding_dim", embed_dim)
            payload.setdefault("vector_backend", "qdrant")
            payload.setdefault("point_key", self._point_key(cid, document_id=document_id, pipeline=pipeline))
            points.append(PointStruct(id=point_id, vector=vec, payload=payload))
        if not points:
            return 0
        batch_size = max(1, int(getattr(config, "QDRANT_UPSERT_BATCH_SIZE", 64) or 64))
        for i in range(0, len(points), batch_size):
            batch = points[i : i + batch_size]
            for attempt in range(3):
                try:
                    client.upsert(collection_name=self._collection, points=batch)
                    break
                except Exception as exc:
                    if attempt >= 2:
                        raise RuntimeError(
                            f"Qdrant upsert failed for batch "
                            f"{i // batch_size + 1} ({len(batch)} points): {exc}"
                        ) from exc
                    print(f"[qdrant] upsert retry {attempt + 1}: {exc}")
        return len(points)

    @staticmethod
    def _sanitize_vector(vec: Any, *, chunk_id: str = "", dim: int | None = None) -> list[float] | None:
        """Convert embedding to plain floats; never drop a chunk for NaN/Inf.

        NaN/Inf dims are zeroed. If the vector is unusable, synthesize a tiny
        deterministic vector from ``chunk_id`` so the point (and payload) still
        lands in Qdrant — full-document coverage over perfect cosine quality.
        """
        import hashlib
        import math

        target_dim = dim
        out: list[float] | None = None
        if vec is not None:
            try:
                if hasattr(vec, "tolist"):
                    vec = vec.tolist()
                out = []
                for x in vec:
                    f = float(x)
                    if math.isnan(f) or math.isinf(f):
                        out.append(0.0)
                    else:
                        out.append(0.0 if f == 0.0 else f)
                target_dim = target_dim or len(out)
            except Exception:
                out = None

        if out is not None and target_dim and len(out) != target_dim:
            out = None

        if out is not None and any(x != 0.0 for x in out):
            return out

        # Deterministic fallback so every chunk gets a Qdrant point.
        d = int(target_dim or dim or 1536)
        seed = hashlib.sha256(f"fallback:{chunk_id}".encode("utf-8")).digest()
        vals: list[float] = []
        while len(vals) < d:
            seed = hashlib.sha256(seed).digest()
            for b in seed:
                vals.append(((b / 255.0) * 2.0) - 1.0)
                if len(vals) >= d:
                    break
        # L2-normalize
        norm = math.sqrt(sum(v * v for v in vals)) or 1.0
        return [v / norm for v in vals[:d]]

    @staticmethod
    def _point_key(chunk_id: str, *, document_id: str = "", pipeline: str = "") -> str:
        """Collision-proof key: pipeline + document + chunk (not bare CHUNK_N)."""
        doc = (document_id or "").strip() or "_"
        pipe = (pipeline or "").strip() or "_"
        return f"{pipe}:{doc}:{chunk_id}"

    @classmethod
    def _point_id(cls, chunk_id: str, *, document_id: str = "", pipeline: str = "") -> str:
        key = cls._point_key(chunk_id, document_id=document_id, pipeline=pipeline)
        # Prefer composite uuid5 always so identical CHUNK_001 across docs never collide.
        return str(uuid.uuid5(uuid.NAMESPACE_URL, key))

    def collection_info(self) -> dict[str, Any]:
        client = self._get_client()
        if not client.collection_exists(self._collection):
            return {}
        info = client.get_collection(self._collection)
        return {
            "name": self._collection,
            "points_count": info.points_count,
            "vector_dim": info.config.params.vectors.size,
            "distance": str(info.config.params.vectors.distance),
            "payload_schema": dict(info.payload_schema or {}),
        }

    def sample_point(self, *, with_vector: bool = False) -> dict[str, Any] | None:
        client = self._get_client()
        if not client.collection_exists(self._collection):
            return None
        records, _ = client.scroll(
            collection_name=self._collection,
            limit=1,
            with_payload=True,
            with_vectors=with_vector,
        )
        if not records:
            return None
        rec = records[0]
        out: dict[str, Any] = {"id": str(rec.id), "payload": rec.payload or {}}
        if with_vector and rec.vector is not None:
            vec = rec.vector
            if isinstance(vec, dict):
                vec = next(iter(vec.values()), [])
            out["vector_len"] = len(vec) if vec else 0
        return out

    def search(
        self,
        query: str,
        *,
        top_k: int = 20,
        filters: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        return self.search_with_metadata_filter(query, top_k=top_k, filters=filters or {})

    def search_cosine_only(
        self,
        query: str,
        *,
        top_k: int = 20,
        filters: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        """Raw cosine top-k — no kind/file/pipeline Python boosts."""
        filters = dict(filters or {})
        client = self._get_client()
        if not client.collection_exists(self._collection):
            return []
        qvec = self._embedder.embed_query(query)

        qfilter = self._build_filter(filters)

        response = client.query_points(
            collection_name=self._collection,
            query=qvec,
            query_filter=qfilter,
            limit=top_k,
            with_payload=True,
        )
        out: list[dict[str, Any]] = []
        for h in response.points or []:
            payload = h.payload or {}
            score = float(h.score or 0.0)
            out.append(self._hit_dict(payload, score, point_id=str(h.id)))
        return out

    def search_with_metadata_filter(
        self,
        query: str,
        *,
        top_k: int = 20,
        filters: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Dense search over the full collection.

        When ``filters['_pure_vector']`` is set, returns raw cosine only.
        Otherwise metadata is used for soft post-rank boosts — never as Qdrant
        ``must`` filters (except optional UI document scope when
        ``filters['_hard_scope']`` is set).
        """
        if filters.get("_pure_vector"):
            return self.search_cosine_only(query, top_k=top_k, filters=filters)

        client = self._get_client()
        if not client.collection_exists(self._collection):
            return []
        qvec = self._embedder.embed_query(query)

        # Soft-only by default: search the whole collection, then boost in Python.
        # Hard filters apply when `_hard_scope` or explicit document/content/pipeline set.
        qfilter = self._build_filter(filters)

        # Over-fetch so soft kind/file boosts can still surface preferred docs.
        fetch_k = max(top_k * 3, top_k, 24)
        response = client.query_points(
            collection_name=self._collection,
            query=qvec,
            query_filter=qfilter,
            limit=fetch_k,
            with_payload=True,
        )
        hits = response.points or []
        wanted_kinds = filters.get("knowledge_kinds") or filters.get("knowledge_kind")
        if isinstance(wanted_kinds, str):
            wanted_kinds = [wanted_kinds]
        wanted_set = {str(k) for k in (wanted_kinds or [])}
        prefer_files = set()
        if filters.get("file_name"):
            prefer_files.add(str(filters["file_name"]))
        for n in filters.get("file_names") or []:
            prefer_files.add(str(n))
        prefer_pipe = str(filters.get("pipeline") or "")

        scored: list[tuple[float, dict[str, Any]]] = []
        for h in hits:
            payload = h.payload or {}
            base = float(h.score or 0.0)
            boost = 0.0
            kind = str(payload.get("knowledge_kind") or "")
            if wanted_set and kind in wanted_set:
                boost += 0.08
            fn = str(payload.get("file_name") or "")
            if prefer_files and any(p in fn for p in prefer_files):
                boost += 0.12
            if prefer_pipe and str(payload.get("pipeline") or "") == prefer_pipe:
                boost += 0.03
            hit = self._hit_dict(payload, base + boost, point_id=str(h.id))
            scored.append((base + boost, hit))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [row for _, row in scored[:top_k]]

    @staticmethod
    def _hit_dict(payload: dict[str, Any], score: float, *, point_id: str = "") -> dict[str, Any]:
        """Normalized retrieval hit with hierarchy fields promoted."""
        return {
            "chunk_id": payload.get("chunk_id", point_id),
            "text": payload.get("text", ""),
            "score": score,
            "document_id": payload.get("document_id"),
            "content_type": payload.get("content_type"),
            "file_name": payload.get("file_name"),
            "section": payload.get("section"),
            "subsection": payload.get("subsection"),
            "toc_path": payload.get("toc_path"),
            "page": payload.get("page"),
            "parent_id": payload.get("parent_id"),
            "prev_chunk_id": payload.get("prev_chunk_id"),
            "next_chunk_id": payload.get("next_chunk_id"),
            "table_id": payload.get("table_id"),
            "row_id": payload.get("row_id"),
            "entities": payload.get("entities") or payload.get("entity_types") or [],
            "content": payload.get("text") or payload.get("content") or "",
            "metadata": payload,
        }

    def _build_filter(self, filters: Optional[dict[str, Any]]):
        """Build Qdrant Filter for document_id / file_name / content_type / pipeline.

        Soft retrieval (default) does not hard-filter. Pass ``_hard_scope`` /
        ``_strict_filter`` or the ``_filter_*`` flags to constrain the search.
        """
        from qdrant_client.models import FieldCondition, Filter, MatchAny, MatchValue

        filters = dict(filters or {})
        must = []
        hard = bool(filters.get("_hard_scope") or filters.get("_strict_filter"))

        if filters.get("document_id") and (hard or filters.get("_filter_document_id")):
            must.append(
                FieldCondition(
                    key="document_id",
                    match=MatchValue(value=str(filters["document_id"])),
                )
            )

        if hard or filters.get("_filter_file_name"):
            fn = filters.get("file_name")
            names = filters.get("file_names")
            if fn:
                must.append(FieldCondition(key="file_name", match=MatchValue(value=fn)))
            elif names:
                if isinstance(names, str):
                    names = [names]
                must.append(FieldCondition(key="file_name", match=MatchAny(any=list(names))))

        cts = filters.get("content_types") or filters.get("content_type")
        if cts and (hard or filters.get("_filter_content_type")):
            if isinstance(cts, str):
                cts = [cts]
            must.append(
                FieldCondition(
                    key="content_type",
                    match=MatchAny(any=[str(c) for c in cts]),
                )
            )

        pipe = filters.get("pipeline")
        if pipe and (hard or filters.get("_filter_pipeline")):
            must.append(FieldCondition(key="pipeline", match=MatchValue(value=str(pipe))))

        if not must:
            return None
        return Filter(must=must)

    def get_chunks_by_ids(
        self,
        chunk_ids: list[str],
        limit: int = 100,
        *,
        document_id: str | None = None,
        file_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch payloads by chunk_id for context expansion.

        Prefer scoping by document_id/file_name — bare chunk_ids collide across
        FS.11 / FS.19 / FS.20 / FS.21 in the shared corpus.
        """
        from qdrant_client.models import FieldCondition, Filter, MatchAny, MatchValue

        ids = [str(c) for c in chunk_ids if c]
        if not ids:
            return []
        client = self._get_client()
        if not client.collection_exists(self._collection):
            return []
        must: list[Any] = [FieldCondition(key="chunk_id", match=MatchAny(any=ids[:limit]))]
        if document_id:
            must.append(FieldCondition(key="document_id", match=MatchValue(value=str(document_id))))
        elif file_name:
            must.append(FieldCondition(key="file_name", match=MatchValue(value=str(file_name))))
        records, _ = client.scroll(
            collection_name=self._collection,
            scroll_filter=Filter(must=must),
            limit=limit,
            with_payload=True,
        )
        out: list[dict[str, Any]] = []
        for r in records or []:
            payload = dict(r.payload or {})
            payload.setdefault("chunk_id", payload.get("chunk_id"))
            out.append(payload)
        return out

    def delete_document(self, document_id: str, *, pipeline: str | None = None) -> int:
        """Delete points for a document. Optionally scope to one pipeline.

        Pipeline scope is required when the same FS PDF exists in both
        ``docling`` and ``original`` corpora — otherwise reindexing original
        wipes the Docling vectors.
        """
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        client = self._get_client()
        if not client.collection_exists(self._collection):
            return 0
        must = [FieldCondition(key="document_id", match=MatchValue(value=document_id))]
        if pipeline:
            must.append(FieldCondition(key="pipeline", match=MatchValue(value=str(pipeline))))
        client.delete(
            collection_name=self._collection,
            points_selector=Filter(must=must),
        )
        return 1

    def get_document_chunks(
        self,
        document_id: str,
        limit: int = 500,
        *,
        pipeline: str | None = None,
    ) -> list[dict[str, Any]]:
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        client = self._get_client()
        if not client.collection_exists(self._collection):
            return []
        must = [FieldCondition(key="document_id", match=MatchValue(value=document_id))]
        if pipeline:
            must.append(FieldCondition(key="pipeline", match=MatchValue(value=str(pipeline))))
        records, _ = client.scroll(
            collection_name=self._collection,
            scroll_filter=Filter(must=must),
            limit=limit,
            with_payload=True,
        )
        return [{"chunk_id": r.payload.get("chunk_id"), **(r.payload or {})} for r in records]


_store: QdrantVectorStore | None = None


def get_qdrant_store() -> QdrantVectorStore:
    global _store
    if _store is None:
        _store = QdrantVectorStore()
    return _store
