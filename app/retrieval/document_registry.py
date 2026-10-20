"""Resolve enrolled documents from query terms, TADIG, IDs, and similarity."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_DOC_ID_RE = re.compile(r"\b(DOC_[A-Za-z0-9_]+)\b")
_TADIG_EXPLICIT_RE = re.compile(r"\bTADIG\s*(?:code)?\s*[:=]?\s*([A-Z]{5})\b", re.I)

_PIPELINE_HINTS = {
    "docling": (
        "table",
        "heading",
        "structure-aware",
    ),
    "original": (
        "fs.19",
        "fs19",
        "diameter interconnect",
        "message screening",
        "diameter firewall",
        "diameter routing agent",
        "3gpp",
        "gtp session",
        "hijack",
    ),
}


@dataclass
class DocumentCandidate:
    file_name: str
    pipeline: str
    score: float = 0.0
    document_id: str | None = None
    tadig: str | None = None
    organisation_name: str | None = None
    source: str | None = None
    match_reasons: list[str] = field(default_factory=list)


def _tokenize(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) >= 3}


def _catalog() -> list[dict[str, Any]]:
    """Enrolled vector documents (standards / tools / TI). IR.21 is SQL-only."""
    from app.ingestion.metadata import infer_document_metadata
    from shared.vector_store import VectorStore

    profiles: dict[str, dict[str, Any]] = {}

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for pipeline in ("docling", "original"):
        try:
            for fn in VectorStore(pipeline).list_documents():
                if _is_ir21_name(fn):
                    continue
                key = (pipeline, fn)
                if key in seen:
                    continue
                seen.add(key)
                meta = infer_document_metadata(fn, pipeline)
                prof = profiles.get(fn) or {}
                rows.append(
                    {
                        "file_name": fn,
                        "pipeline": pipeline,
                        "document_id": prof.get("document_id"),
                        "tadig": (prof.get("tadig") or "").upper() or None,
                        "organisation_name": prof.get("organisation_name"),
                        "country": prof.get("country"),
                        "title": prof.get("title") or fn,
                        "source": meta.get("source"),
                        "document_type": meta.get("document_type"),
                        "search_text": " ".join(
                            str(x)
                            for x in (
                                fn,
                                prof.get("title"),
                                prof.get("organisation_name"),
                                prof.get("tadig"),
                                prof.get("country"),
                                meta.get("source"),
                            )
                            if x
                        ).lower(),
                    }
                )
        except Exception:
            continue
    return rows


def _is_ir21_name(file_name: str) -> bool:
    fn = (file_name or "").lower()
    return "ir21" in fn or "ir.21" in fn or "raex" in fn


def _known_tadigs() -> set[str]:
    try:
        from ir21.postgres import list_documents

        return {
            str(d.get("tadig") or "").upper()
            for d in list_documents()
            if d.get("tadig")
        }
    except Exception:
        return set()


def extract_identifiers(query: str, entities: dict[str, Any] | None = None) -> dict[str, Any]:
    entities = entities or {}
    out: dict[str, Any] = {}
    q = query or ""

    if entities.get("tadig"):
        out["tadig"] = str(entities["tadig"]).upper()
    m = _TADIG_EXPLICIT_RE.search(q)
    if m:
        out["tadig"] = m.group(1).upper()

    if not out.get("tadig"):
        known = _known_tadigs()
        for m in re.finditer(r"\b([A-Z]{5})\b", q):
            code = m.group(1).upper()
            if code in known:
                out["tadig"] = code
                break

    m = _DOC_ID_RE.search(q)
    if m:
        out["document_id"] = m.group(1)

    return out


def resolve_documents(
    query: str,
    *,
    document: str | None = None,
    entities: dict[str, Any] | None = None,
) -> list[DocumentCandidate]:
    """Rank enrolled documents by TADIG, ID, filename, taxonomy FS routing, and term overlap."""
    from app.ontology.taxonomy import demoted_fs_documents_for_query, fs_documents_for_query

    catalog = _catalog()
    if not catalog:
        return []

    if document:
        for row in catalog:
            if row["file_name"] == document or document in row["file_name"]:
                return [
                    DocumentCandidate(
                        file_name=row["file_name"],
                        pipeline=row["pipeline"],
                        score=100.0,
                        document_id=row.get("document_id"),
                        tadig=row.get("tadig"),
                        organisation_name=row.get("organisation_name"),
                        source=row.get("source"),
                        match_reasons=["explicit_document"],
                    )
                ]
        from shared.vector_store import VectorStore

        pipeline = "docling"
        for p in ("docling", "original"):
            docs = VectorStore(p).list_documents()
            if document in docs or any(document in d for d in docs):
                pipeline = p
                break
        return [
            DocumentCandidate(
                file_name=document,
                pipeline=pipeline,
                score=100.0,
                match_reasons=["explicit_document"],
            )
        ]

    ids = extract_identifiers(query, entities)
    q = (query or "").lower()
    q_tokens = _tokenize(query)
    q_compact = re.sub(r"[^a-z0-9]+", "", q)
    preferred_fs = fs_documents_for_query(query)
    demoted_fs = demoted_fs_documents_for_query(query)
    primary_fs = preferred_fs[0] if preferred_fs and preferred_fs[0] in ("FS.11", "FS.19", "FS.20") else ""

    candidates: list[DocumentCandidate] = []
    for row in catalog:
        score = 0.0
        reasons: list[str] = []
        fn = row["file_name"]
        fn_low = fn.lower()

        if ids.get("document_id") and row.get("document_id") == ids["document_id"]:
            score += 50.0
            reasons.append("document_id")

        if ids.get("tadig") and row.get("tadig") == ids["tadig"]:
            score += 40.0
            reasons.append("tadig")

        for part in re.split(r"[^a-z0-9]+", fn_low):
            if len(part) >= 4 and part in q_compact:
                score += 6.0
                reasons.append(f"filename:{part}")
                break

        org = (row.get("organisation_name") or "").lower()
        if org and len(org) >= 4 and org in q:
            score += 8.0
            reasons.append("organisation")

        if row.get("tadig") and row["tadig"].lower() in q:
            score += 35.0
            reasons.append("tadig_in_text")

        overlap = q_tokens & _tokenize(row.get("search_text") or fn_low)
        if overlap:
            score += min(len(overlap) * 1.5, 8.0)
            reasons.append(f"terms:{','.join(sorted(overlap)[:4])}")

        for hint in _PIPELINE_HINTS.get(row["pipeline"], ()):
            if hint in q:
                score += 2.0
                reasons.append(f"pipeline_hint:{hint}")

        # Protocol primary (FS.11/19/20) >> FS.21 umbrella >> wrong-protocol docs.
        if primary_fs and primary_fs.lower() in fn_low:
            score += 55.0
            reasons.append(f"primary:{primary_fs}")
        elif preferred_fs:
            for i, fs_tag in enumerate(preferred_fs):
                if fs_tag.lower() in fn_low:
                    # FS.21 after a primary is only a weak secondary.
                    if fs_tag == "FS.21" and primary_fs:
                        score += 6.0
                        reasons.append("umbrella:FS.21")
                    else:
                        score += 32.0 - (i * 5.0)
                        reasons.append(f"taxonomy:{fs_tag}")
                    break
        for fs_tag in demoted_fs:
            if fs_tag.lower() in fn_low:
                # Wrong protocol or umbrella when primary exists.
                penalty = 40.0 if fs_tag == "FS.21" and primary_fs else 28.0
                score -= penalty
                reasons.append(f"demote:{fs_tag}")

        if score > 0:
            candidates.append(
                DocumentCandidate(
                    file_name=fn,
                    pipeline=row["pipeline"],
                    score=score,
                    document_id=row.get("document_id"),
                    tadig=row.get("tadig"),
                    organisation_name=row.get("organisation_name"),
                    source=row.get("source"),
                    match_reasons=reasons,
                )
            )

    # If the detailed primary (e.g. FS.11) is not enrolled, fall back to FS.21 for that protocol.
    if primary_fs and not any(primary_fs.lower() in (c.file_name or "").lower() for c in candidates):
        rescued: list[DocumentCandidate] = []
        for row in catalog:
            fn_low = (row["file_name"] or "").lower()
            if "fs.21" not in fn_low:
                continue
            if _is_ir21_name(row["file_name"]):
                continue
            rescued.append(
                DocumentCandidate(
                    file_name=row["file_name"],
                    pipeline=row["pipeline"],
                    score=45.0,
                    document_id=row.get("document_id"),
                    tadig=row.get("tadig"),
                    organisation_name=row.get("organisation_name"),
                    source=row.get("source"),
                    match_reasons=[f"fallback_umbrella_for_missing:{primary_fs}"],
                )
            )
        if rescued:
            # Drop wrong-protocol docs that survived demotion; keep tools only if no FS.21.
            candidates = [
                c for c in candidates
                if not any(tag in (c.file_name or "").lower() for tag in ("fs.19", "fs.20", "fs.11") if tag != primary_fs.lower())
            ]
            candidates.extend(rescued)

    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates


def infer_retrieval_scope(
    query: str,
    *,
    document: str | None = None,
    entities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build retrieval filters: pipelines, file_name(s), tadig, document_id.

    Single-document pin only when confidence is high; otherwise search broadly
    and let reranking prefer top candidates.
    """
    scope: dict[str, Any] = {}
    ids = extract_identifiers(query, entities)
    if ids.get("tadig"):
        scope["tadig"] = ids["tadig"]
    if ids.get("document_id"):
        scope["document_id"] = ids["document_id"]

    candidates = resolve_documents(query, document=document, entities=entities)
    if not candidates:
        q = (query or "").lower()
        docling_hits = sum(1 for h in _PIPELINE_HINTS["docling"] if h in q)
        orig_hits = sum(1 for h in _PIPELINE_HINTS["original"] if h in q)
        if docling_hits > orig_hits and docling_hits > 0:
            scope["pipelines"] = ["docling"]
        elif orig_hits > docling_hits and orig_hits > 0:
            scope["pipelines"] = ["original"]
        return scope

    top = candidates[0]
    second = candidates[1].score if len(candidates) > 1 else 0.0
    gap = top.score - second

    if document or (top.score >= 35 and gap >= 8):
        scope["file_name"] = top.file_name
        if top.document_id:
            scope["document_id"] = top.document_id
        if top.tadig:
            scope["tadig"] = top.tadig
    elif top.score >= 12 and gap >= 4:
        scope["file_name"] = top.file_name
        if top.document_id:
            scope["document_id"] = top.document_id
        if top.tadig:
            scope["tadig"] = top.tadig
    elif len(candidates) > 1 and top.score >= 8:
        scope["file_names"] = [c.file_name for c in candidates[:3] if c.score >= top.score * 0.5]
        scope["candidate_scores"] = {c.file_name: c.score for c in candidates[:5]}

    pipelines = sorted({c.pipeline for c in candidates[:3]})
    import config

    preferred_pipe = config.DOCUMENT_PIPELINE
    if preferred_pipe in pipelines:
        pipelines = [preferred_pipe]
    elif pipelines:
        pipelines = [pipelines[0]]
    q = (query or "").lower()
    docling_hits = sum(1 for h in _PIPELINE_HINTS["docling"] if h in q)
    orig_hits = sum(1 for h in _PIPELINE_HINTS["original"] if h in q)
    if docling_hits > orig_hits and docling_hits > 0:
        pipelines = [p for p in pipelines if p == "docling"] or ["docling"]
    elif orig_hits > docling_hits and orig_hits > 0:
        pipelines = [p for p in pipelines if p == "original"] or ["original"]
    if pipelines:
        scope["pipelines"] = pipelines

    # Keep explicit document filter authoritative
    if document:
        scope["file_name"] = document
        for c in candidates:
            if c.file_name == document:
                if c.document_id:
                    scope["document_id"] = c.document_id
                if c.tadig:
                    scope["tadig"] = c.tadig
                break

    return scope
