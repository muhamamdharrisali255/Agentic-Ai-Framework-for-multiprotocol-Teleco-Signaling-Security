"""Docling pipeline — structured extraction to embeddings + hybrid stores."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import config
from docling_pipeline.canonical import build_canonical_from_docling_export, canonical_to_chunks
from docling_pipeline.extractor import extract_with_docling, save_canonical_json
from shared.hybrid_index import index_hybrid_layers
from shared.schema import CanonicalDocument, ChunkRecord


def process_document(path: Path, save_intermediate: bool = True) -> List[ChunkRecord]:
    export = extract_with_docling(path)

    if save_intermediate:
        out_dir = config.CANONICAL_DIR / path.stem
        out_dir.mkdir(parents=True, exist_ok=True)
        save_canonical_json(export, out_dir / "docling_export.json")

    canonical = build_canonical_from_docling_export(export, path.name)
    if save_intermediate:
        canon_path = config.CANONICAL_DIR / path.stem / "canonical.json"
        canon_path.write_text(canonical.model_dump_json(indent=2), encoding="utf-8")

    chunks = canonical_to_chunks(canonical)

    # Hybrid layers: Postgres/SQLite structured IR.21 + Neo4j/JSON entity graph
    try:
        stats = index_hybrid_layers(canonical, chunks)
        print(
            f"[hybrid] {path.name}: entities={stats['entities']} "
            f"relations={stats['relations']} graph={stats['graph_backend']}"
        )
        if save_intermediate:
            hybrid_path = config.CANONICAL_DIR / path.stem / "hybrid_stats.json"
            hybrid_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"[hybrid] warning: failed to index structured/graph layers: {exc}")

    return chunks


def load_canonical(path: Path) -> CanonicalDocument:
    data = json.loads(path.read_text(encoding="utf-8"))
    return CanonicalDocument.model_validate(data)
