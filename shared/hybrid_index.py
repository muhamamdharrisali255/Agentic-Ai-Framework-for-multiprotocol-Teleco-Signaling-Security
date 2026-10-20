"""Entity/relation layer built alongside the vector index.

RAEX IR.21 documents no longer pass through here: they are detected at
enrollment and loaded into the relational store (see ``ir21.ingest``). What
remains is named-entity extraction over prose specifications, kept behind
``ENABLE_GRAPH_LAYER`` because no retrieval route reads the graph today.
"""

from __future__ import annotations

from typing import List

import config
from docling_pipeline.entity_extractor import extract_entities, relations_from_entities
from shared.ir21_schema import RelationRecord
from shared.neo4j_store import get_graph_store
from shared.schema import CanonicalDocument, ChunkRecord, EntityRecord


def index_hybrid_layers(canonical: CanonicalDocument, chunks: List[ChunkRecord]) -> dict:
    """Extract entities and relations for a prose document."""
    from shared.ids import doc_id as make_doc_id

    stable_id = make_doc_id(canonical.file_name)
    if canonical.document_id != stable_id:
        canonical.document_id = stable_id
        for ch in chunks:
            ch.document_id = stable_id
            for e in ch.entities or []:
                e.document_id = stable_id

    entities: List[EntityRecord] = []
    relations: List[RelationRecord] = []

    for ch in chunks:
        entities.extend(ch.entities or [])

    for sec in canonical.sections:
        blob_parts = [sec.title] + list(sec.content or [])
        for tbl in sec.tables or []:
            blob_parts.extend(tbl.headers or [])
            for row in tbl.rows or []:
                if isinstance(row, dict):
                    blob_parts.extend(f"{k}:{v}" for k, v in row.items())
        blob = "\n".join(str(p) for p in blob_parts if p)
        entities.extend(
            extract_entities(
                blob,
                document_id=canonical.document_id,
                section_id=sec.section_id,
                page=sec.page_start,
            )
        )

    seen: set[tuple[str, str]] = set()
    uniq_entities: List[EntityRecord] = []
    for e in entities:
        key = (e.type, e.entity.lower())
        if key in seen:
            continue
        seen.add(key)
        uniq_entities.append(e)

    relations.extend(relations_from_entities(uniq_entities, file_name=canonical.file_name))

    rseen: set[tuple[str, str, str]] = set()
    uniq_rels: List[RelationRecord] = []
    for r in relations:
        key = (r.subject.lower(), r.predicate, r.object.lower())
        if key in rseen:
            continue
        rseen.add(key)
        uniq_rels.append(r)

    graph_backend = "disabled"
    if config.ENABLE_GRAPH_LAYER:
        graph = get_graph_store()
        graph.delete_by_file_name(canonical.file_name)
        graph.replace_document_graph(
            document_id=canonical.document_id,
            file_name=canonical.file_name,
            entities=uniq_entities,
            relations=uniq_rels,
        )
        graph_backend = graph.backend

    return {
        "entities": len(uniq_entities),
        "relations": len(uniq_rels),
        "graph_backend": graph_backend,
    }
