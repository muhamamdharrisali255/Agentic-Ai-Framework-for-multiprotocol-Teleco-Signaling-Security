"""Index a document through a specified pipeline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import config
from shared.ids import reset_ids
from shared.index_report import build_index_report
from shared.schema import ChunkRecord
from shared.vector_store import VectorStore


def build_structured_report(file_name: str, stats: dict) -> str:
    counts = stats.get("counts") or {}
    lines = [
        f"## Structured enrollment — {file_name}",
        "",
        f"- **Route**: RAEX IR.21 template detected → PostgreSQL (not embedded)",
        f"- **Document ID**: {stats.get('document_id')}",
        f"- **Operator**: {stats.get('organisation') or 'n/a'} (TADIG {stats.get('tadig') or 'n/a'})",
        f"- **Total records**: {stats.get('records', 0)}",
        "",
        "| Relation | Rows |",
        "| :--- | ---: |",
    ]
    lines.extend(f"| {name.replace('_', ' ')} | {count} |" for name, count in counts.items() if count)
    return "\n".join(lines)


def index_document(
    path: Path,
    pipeline: str,
    force: bool = False,
    return_report: bool = False,
) -> int | tuple[int, str]:
    reset_ids()
    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(path)

    # RAEX IR.21 is a filled-in form: it belongs in the relational store, and
    # embedding its cells would only add noise to the document corpus.
    from ir21.ingest import is_ir21_pdf

    if is_ir21_pdf(path):
        from ir21.ingest import ingest as ingest_ir21

        stats = ingest_ir21(path)
        if "documents" in stats:
            print(
                f"Routed {path.name} to structured storage: "
                f"{stats['records']} records across {len(stats['documents'])} IR.21 filing(s)"
            )
            for doc in stats["documents"]:
                print(
                    f"  - {doc.get('tadig') or 'n/a'} ({doc.get('organisation') or 'n/a'}): "
                    f"{doc['records']} rows"
                )
            if return_report:
                return 0, "\n\n".join(
                    build_structured_report(d.get("file_name") or path.name, d)
                    for d in stats["documents"]
                )
            return 0
        print(
            f"Routed {path.name} to structured storage: "
            f"{stats['records']} records in PostgreSQL "
            f"(TADIG {stats['tadig'] or 'n/a'}, document {stats['document_id']})"
        )
        if return_report:
            return 0, build_structured_report(path.name, stats)
        return 0

    if pipeline == "original":
        from original.pipeline import process_document
    elif pipeline == "docling":
        from docling_pipeline.pipeline import process_document
    else:
        raise ValueError(f"Unknown pipeline: {pipeline}")

    chunks: list[ChunkRecord] = process_document(path)
    try:
        from app.ingestion.chunk_taxonomy import tag_chunks

        chunks = tag_chunks(chunks)
    except Exception as exc:
        print(f"[taxonomy] chunk tagging skipped: {exc}")
    store = VectorStore(pipeline)
    count = store.build(chunks, force=force)
    print(f"Indexed {count} chunks from {path.name} via pipeline={pipeline}")
    try:
        from collections import Counter

        from app.ingestion.qdrant_indexer import format_indexing_stats
        from app.config.settings import settings

        type_counts = Counter(c.content_type.value for c in chunks)
        n_headings = type_counts.get("heading", 0)
        stats_text = format_indexing_stats(
            chunks,
            file_name=path.name,
            embeddings=count,
            qdrant_points=count,
            collection=getattr(config, "DOCLING_QDRANT_COLLECTION", None)
            or settings.qdrant_collection,
            sections=n_headings,
        )
        print(stats_text)
    except Exception as exc:
        print(f"[index] stats summary skipped: {exc}")
    if return_report:
        return count, build_index_report(chunks, pipeline, path.name)
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Index a document")
    parser.add_argument("document", type=Path)
    parser.add_argument("--pipeline", choices=["original", "docling"], default=config.DOCUMENT_PIPELINE)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        index_document(args.document, args.pipeline, force=args.force)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
