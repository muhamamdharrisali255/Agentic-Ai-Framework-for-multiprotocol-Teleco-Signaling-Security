"""Index chunks into Qdrant with enriched metadata."""

from __future__ import annotations

import logging
import sys
import time
from collections import Counter
from typing import Any

import config
from app.ingestion.metadata import chunk_to_qdrant_payload, infer_document_metadata
from app.retrieval.qdrant_store import get_qdrant_store
from shared.schema import ChunkRecord, ContentType
from shared.vector_store import VectorStore

logger = logging.getLogger(__name__)


def chunks_from_pipeline(pipeline: str = "docling") -> list[ChunkRecord]:
    store = VectorStore(pipeline)
    if not store.chunks_path.exists():
        return []
    store.load()
    return list(store._chunks or [])


def index_chunks_to_qdrant(
    chunks: list[ChunkRecord],
    *,
    source: str = "docling",
    batch_size: int | None = None,
    progress_every: int = 1,
    purge_document: bool = True,
) -> int:
    """Embed + upsert chunks. Deletes prior points for each document_id first.

    Deterministic point IDs + document-scoped delete make re-indexing idempotent
    and remove obsolete chunks when a document shrinks.
    """
    if not chunks:
        return 0
    from app.ingestion.embed_text import is_indexable_chunk

    before = len(chunks)
    indexable = [c for c in chunks if is_indexable_chunk(c)]
    skipped = before - len(indexable)
    if skipped:
        print(f"[qdrant] skipped {skipped} non-indexable ToC/junk chunks", flush=True)
        logger.info(
            "qdrant_index skip non_indexable=%s indexable=%s",
            skipped,
            len(indexable),
        )
    if not indexable:
        return 0

    batch_size = int(
        batch_size
        if batch_size is not None
        else getattr(config, "QDRANT_UPSERT_BATCH_SIZE", 64) or 64
    )

    qdrant = get_qdrant_store()
    if not qdrant.is_available():
        raise RuntimeError("Qdrant unavailable — cannot index chunks")
    qdrant.create_collection()

    if purge_document:
        doc_ids = sorted({c.document_id for c in indexable if c.document_id})
        for did in doc_ids:
            try:
                qdrant.delete_document(did, pipeline=source)
                logger.info(
                    "qdrant_purged document_id=%s pipeline=%s before reindex",
                    did,
                    source,
                )
                print(
                    f"[qdrant] purged prior points for document_id={did} pipeline={source}",
                    flush=True,
                )
            except Exception as exc:
                logger.warning("qdrant purge failed document_id=%s: %s", did, exc)
                print(f"[qdrant] purge warning for {did}: {exc}", flush=True)

    by_doc: dict[str, dict[str, Any]] = {}
    total = 0
    n_batches = (len(indexable) + batch_size - 1) // batch_size
    t0 = time.time()
    for batch_num, i in enumerate(range(0, len(indexable), batch_size), start=1):
        batch = indexable[i : i + batch_size]
        payloads: list[dict[str, Any]] = []
        for ch in batch:
            fn = ch.file_name or ch.document_id
            if fn not in by_doc:
                by_doc[fn] = infer_document_metadata(fn, source)
            payload = chunk_to_qdrant_payload(ch, by_doc[fn])
            payload["pipeline"] = source
            payloads.append(payload)
        try:
            total += qdrant.upsert_chunks(payloads, ensure_collection=False)
        except Exception as exc:
            logger.exception(
                "qdrant upsert failed document batch=%s/%s size=%s",
                batch_num,
                n_batches,
                len(payloads),
            )
            raise RuntimeError(
                f"Qdrant upsert failed at batch {batch_num}/{n_batches}: {exc}"
            ) from exc
        if batch_num % progress_every == 0 or batch_num == n_batches:
            elapsed = time.time() - t0
            pct = 100.0 * total / len(indexable)
            rate = total / elapsed if elapsed > 0 else 0.0
            eta_s = (len(indexable) - total) / rate if rate > 0 else 0.0
            eta_m = int(eta_s // 60)
            eta_r = int(eta_s % 60)
            print(
                f"[qdrant] {total}/{len(indexable)} ({pct:.1f}%) "
                f"batch {batch_num}/{n_batches} "
                f"{rate:.2f} chunks/s ETA {eta_m}m{eta_r:02d}s",
                flush=True,
            )
            sys.stdout.flush()

    logger.info(
        "qdrant_index_complete chunks=%s points=%s collection=%s",
        len(indexable),
        total,
        getattr(qdrant, "_collection", ""),
    )
    return total


def format_indexing_stats(
    chunks: list[ChunkRecord],
    *,
    file_name: str,
    embeddings: int,
    qdrant_points: int,
    collection: str,
    sections: int | None = None,
) -> str:
    counts = Counter(c.content_type.value for c in chunks)
    n_sections = sections
    if n_sections is None:
        n_sections = len({c.section for c in chunks if c.content_type == ContentType.HEADING})
    lines = [
        f"Document: {file_name}",
        "",
        f"Sections:       {n_sections}",
        f"Headings:       {counts.get('heading', 0)}",
        f"Paragraphs:     {counts.get('paragraph', 0) + counts.get('list_item', 0)}",
        f"Tables:         {counts.get('table', 0)}",
        f"Table Rows:     {counts.get('table_row', 0)}",
        f"TOC Chunks:     {counts.get('toc', 0)}",
        f"Total Chunks:   {len(chunks)}",
        "",
        f"Embeddings:     {embeddings}",
        f"Qdrant Points:  {qdrant_points}",
        "",
        f"Collection: {collection}",
        "",
        "Indexing completed successfully.",
    ]
    return "\n".join(lines)


def sync_pipeline_to_qdrant(pipeline: str = "docling") -> int:
    chunks = chunks_from_pipeline(pipeline)
    return index_chunks_to_qdrant(chunks, source=pipeline)
