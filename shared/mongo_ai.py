"""MongoDB AI helpers: Voyage embeddings (MongoDB AI) + LLM structured extract."""

from __future__ import annotations

import json
import re
from typing import Any, Optional

import config
from shared.ir21_schema import IR21Endpoint, IR21Field, IR21Profile
from shared.schema import CanonicalDocument


def voyage_embed(texts: list[str]) -> list[list[float]]:
    """Embed via Voyage AI (MongoDB's AI embedding partner). Empty if not configured."""
    key = (config.VOYAGE_API_KEY or "").strip()
    if not key or not texts:
        return []
    try:
        import requests

        model = config.VOYAGE_EMBED_MODEL
        resp = requests.post(
            "https://api.voyageai.com/v1/embeddings",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"input": texts, "model": model},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json().get("data") or []
        data = sorted(data, key=lambda x: x.get("index", 0))
        return [row.get("embedding") or [] for row in data]
    except Exception as exc:
        print(f"[mongo_ai] Voyage embed failed: {exc}")
        return []


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return float(dot / (na * nb))


def _canonical_text(doc: CanonicalDocument, max_chars: int = 14000) -> str:
    parts: list[str] = [f"File: {doc.file_name}", f"Title: {doc.title}"]
    for sec in doc.sections:
        parts.append(f"\n## {sec.title} (section_id={sec.section_id}, page={sec.page_start})")
        for para in (sec.content or [])[:40]:
            parts.append(str(para))
        for tbl in sec.tables or []:
            headers = tbl.headers or []
            parts.append("TABLE headers: " + " | ".join(str(h) for h in headers))
            for row in (tbl.rows or [])[:30]:
                if isinstance(row, dict):
                    parts.append(" | ".join(f"{k}={v}" for k, v in row.items()))
                else:
                    parts.append(str(row))
    text = "\n".join(parts)
    return text[:max_chars]


def extract_ir21_profile_ai(doc: CanonicalDocument) -> Optional[IR21Profile]:
    """
    Extract IR.21 structured facts with the local LLM and store-ready profile.
    Used as MongoDB-oriented AI extraction (Document Intelligence style).
    """
    from docling_pipeline.ir21_extractor import is_ir21_document
    from shared.llm import answer_question_raw, is_llm_available

    if not is_ir21_document(doc):
        return None
    if not is_llm_available():
        return None

    blob = _canonical_text(doc)
    prompt = (
        "Extract structured facts from this interconnect / network document.\n"
        "Return ONLY valid JSON (no markdown) matching this schema:\n"
        "{\n"
        '  "organisation_name": "", "country": "", "tadig": "", "mcc": "", "mnc": "",\n'
        '  "creation_date": "", "effective_date": "", "network_type": "",\n'
        '  "fields": [{"field_key": "", "field_value": "", "section_id": "", "page": null}],\n'
        '  "endpoints": [{"role": "", "node_type": "", "gt_address": "", "fqdn": "", '
        '"ip": "", "ip_secondary": "", "protocol": "", "section_id": "", "page": null}]\n'
        "}\n"
        "Rules:\n"
        "- Fill schema fields only when present in the text; do not invent.\n"
        "- Prefer exact values; keep fields/endpoints concise "
        "(max ~40 fields, ~30 endpoints).\n\n"
        f"DOCUMENT:\n{blob}\n\nJSON:"
    )
    try:
        raw = answer_question_raw(prompt, max_tokens=1800)
    except Exception as exc:
        print(f"[mongo_ai] extract failed: {exc}")
        return None

    data = _parse_json_object(raw)
    if not data:
        return None

    fields = [
        IR21Field(
            field_key=str(f.get("field_key") or "").strip(),
            field_value=str(f.get("field_value") or "").strip(),
            section_id=str(f.get("section_id") or "") or None,
            page=f.get("page"),
            confidence=0.85,
        )
        for f in (data.get("fields") or [])
        if str(f.get("field_key") or "").strip() and str(f.get("field_value") or "").strip()
    ][:60]

    endpoints = [
        IR21Endpoint(
            role=str(ep.get("role") or "").strip(),
            node_type=str(ep.get("node_type") or "").strip(),
            gt_address=str(ep.get("gt_address") or "").strip(),
            fqdn=str(ep.get("fqdn") or "").strip(),
            ip=str(ep.get("ip") or "").strip(),
            ip_secondary=str(ep.get("ip_secondary") or "").strip(),
            protocol=str(ep.get("protocol") or "").strip(),
            section_id=str(ep.get("section_id") or "") or None,
            page=ep.get("page"),
        )
        for ep in (data.get("endpoints") or [])
        if any(
            str(ep.get(k) or "").strip()
            for k in ("role", "node_type", "gt_address", "fqdn", "ip")
        )
    ][:40]

    return IR21Profile(
        document_id=doc.document_id,
        file_name=doc.file_name,
        title=doc.title or "",
        organisation_name=str(data.get("organisation_name") or ""),
        country=str(data.get("country") or ""),
        tadig=str(data.get("tadig") or ""),
        network_type=str(data.get("network_type") or ""),
        creation_date=str(data.get("creation_date") or ""),
        effective_date=str(data.get("effective_date") or ""),
        mcc=str(data.get("mcc") or ""),
        mnc=str(data.get("mnc") or ""),
        fields=fields,
        endpoints=endpoints,
        metadata={"extract": "mongo_ai"},
    )


def _parse_json_object(raw: str) -> Optional[dict[str, Any]]:
    text = (raw or "").strip()
    if not text:
        return None
    # Strip fences
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None
