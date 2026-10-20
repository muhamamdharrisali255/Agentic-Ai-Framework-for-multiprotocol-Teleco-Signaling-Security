"""Chunk metadata enrichment for Qdrant payloads (implementation_plan.md §8)."""

from __future__ import annotations

import re
from typing import Any, Optional

import config
from shared.schema import ChunkRecord, ContentType

from app.ingestion.chunk_profiles import resolve_chunk_profile


def infer_document_metadata(file_name: str, pipeline: str) -> dict[str, str]:
    fn = (file_name or "").lower()
    meta: dict[str, str] = {
        "source": "default",
        "document_type": "document",
        "domain": "general",
        "protocol": "",
        "series": "",
    }
    if "ir21" in fn or "ir.21" in fn or "raex" in fn:
        meta.update(source="RAEX", document_type="ir21", domain="roaming", knowledge_kind="policy")
    elif "3gpp" in fn or fn.startswith("ts"):
        meta.update(source="3GPP", document_type="specification", domain="telecom_security", knowledge_kind="standard")
        m = re.search(r"ts\s*(\d{2})", fn)
        if m:
            meta["series"] = m.group(1)
    elif "gsma" in fn or "fs." in fn:
        meta.update(source="GSMA", document_type="specification", domain="telecom_security", knowledge_kind="standard")
        if "diameter" in fn:
            meta["protocol"] = "Diameter"
    elif "etsi" in fn:
        meta.update(source="ETSI", document_type="specification", knowledge_kind="standard")
    elif "tshark" in fn or "wireshark" in fn:
        meta.update(source="TOOL", document_type="tool", domain="telecom_security", knowledge_kind="tool")
    elif "suricata" in fn:
        meta.update(source="TOOL", document_type="tool", domain="telecom_security", knowledge_kind="tool")
    elif "policy" in fn or "security" in fn:
        meta.update(document_type="policy", domain="telecom_security")
    from app.ingestion.knowledge_kind import infer_knowledge_kind

    meta.setdefault("knowledge_kind", infer_knowledge_kind(file_name, source=meta.get("source", ""), document_type=meta.get("document_type", "")))
    try:
        from ir21.postgres import list_documents

        for row in list_documents():
            if (row.get("file_name") or "") == (file_name or ""):
                if row.get("tadig"):
                    meta["tadig"] = str(row["tadig"]).upper()
                if row.get("organisation_name"):
                    meta["organisation_name"] = row["organisation_name"]
                if row.get("document_id"):
                    meta["document_id"] = row["document_id"]
                break
    except Exception:
        pass
    return meta


def chunk_to_qdrant_payload(chunk: ChunkRecord, doc_meta: Optional[dict[str, str]] = None) -> dict[str, Any]:
    dm = doc_meta or infer_document_metadata(chunk.file_name or "", chunk.pipeline)
    profile = resolve_chunk_profile(
        source=dm.get("source"),
        document_type=dm.get("document_type"),
        file_name=chunk.file_name,
    )
    heading_path = [p for p in (chunk.toc_path or chunk.section or "").split(" > ") if p]
    base = chunk.to_metadata()
    return {
        # Identity
        "chunk_id": chunk.chunk_id,
        "document_id": chunk.document_id or dm.get("document_id", ""),
        "document_title": chunk.file_name or chunk.document_id,
        "file_name": chunk.file_name,
        "pipeline": chunk.pipeline,
        # Document taxonomy
        "source": dm.get("source", ""),
        "series": dm.get("series", ""),
        "document_type": dm.get("document_type", ""),
        "version": dm.get("version", ""),
        "domain": dm.get("domain", ""),
        "protocol": dm.get("protocol", ""),
        "knowledge_kind": dm.get("knowledge_kind", ""),
        "tadig": dm.get("tadig", ""),
        "organisation_name": dm.get("organisation_name", ""),
        # Location in document
        "page": chunk.page,
        "section": chunk.section,
        "subsection": chunk.subsection,
        "toc_path": chunk.toc_path,
        "heading_path": heading_path,
        "source_location": chunk.source_location,
        # Structure / neighbors (for parent-chain expansion)
        "content_type": chunk.content_type.value if chunk.content_type else "text",
        "table_id": chunk.table_id,
        "row_id": chunk.row_id,
        "parent_id": chunk.parent_id,
        "prev_chunk_id": chunk.prev_chunk_id,
        "next_chunk_id": chunk.next_chunk_id,
        "chunk_profile_max_chars": profile.max_chunk_chars,
        # Retrieval text
        "text": chunk.content,
        # Provenance (filled at upsert if omitted)
        "embedding_model": config.EMBEDDING_MODEL,
        "vector_backend": "qdrant",
        # Optional entity tags (compact + full list for retrieval)
        "entities": [e.model_dump() for e in (chunk.entities or [])][:40],
        "entity_count": len(chunk.entities or []),
        "entity_types": sorted({e.type for e in (chunk.entities or []) if e.type})[:12],
    }
