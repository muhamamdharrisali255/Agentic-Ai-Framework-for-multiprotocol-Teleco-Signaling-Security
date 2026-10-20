"""MongoDB structured store for IR.21 facts (replaces Postgres).

Uses:
  - MongoDB document collections for documents / fields / endpoints
  - Optional Voyage AI embeddings (MongoDB AI) for semantic fact retrieval
  - Lexical + semantic fusion for search_facts
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

import config
from shared.ir21_schema import IR21Profile
from shared.mongo_ai import cosine, voyage_embed
from shared.postgres_store import (
    _GENERIC_QUERY_TOKENS,
    _field_token_score,
    _query_tokens,
    _role_parts,
    _select_facts_for_query,
    _token_role_match,
    _word_in,
)


def _search_text_doc(profile: IR21Profile) -> str:
    return " ".join(
        str(x)
        for x in (
            profile.file_name,
            profile.title,
            profile.organisation_name,
            profile.tadig,
            profile.mcc,
            profile.mnc,
            profile.country,
            profile.network_type,
        )
        if x
    )


def _search_text_field(f) -> str:
    return f"{f.field_key} {f.field_value} {f.section_title or ''}".strip()


def _search_text_endpoint(ep) -> str:
    return " ".join(
        str(x)
        for x in (
            ep.role,
            ep.node_type,
            ep.node_id,
            ep.gt_address,
            ep.fqdn,
            ep.ip,
            ep.ip_secondary,
            ep.protocol,
            ep.vendor,
        )
        if x
    )


class MongoStructuredStore:
    """IR.21 structured facts in MongoDB."""

    def __init__(self) -> None:
        from pymongo import MongoClient

        self._client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=4000)
        self._client.admin.command("ping")
        self._db = self._client[config.MONGO_DB]
        self._docs = self._db["ir21_documents"]
        self._fields = self._db["ir21_fields"]
        self._endpoints = self._db["ir21_endpoints"]
        self._ensure_indexes()
        self._backend = "mongo"
        print(f"[structured_store] MongoDB connected · db={config.MONGO_DB}")

    def _ensure_indexes(self) -> None:
        self._docs.create_index("file_name")
        self._docs.create_index("tadig")
        self._fields.create_index([("document_id", 1), ("field_key", 1)])
        self._fields.create_index("file_name")
        self._endpoints.create_index([("document_id", 1), ("role", 1)])
        self._endpoints.create_index("file_name")
        self._endpoints.create_index("gt_address")

    @property
    def backend(self) -> str:
        return self._backend

    def upsert_profile(self, profile: IR21Profile) -> None:
        self.delete_document(profile.document_id)
        now = datetime.now(timezone.utc).isoformat()

        doc = {
            "document_id": profile.document_id,
            "file_name": profile.file_name,
            "title": profile.title,
            "organisation_name": profile.organisation_name,
            "country": profile.country,
            "tadig": profile.tadig,
            "network_type": profile.network_type,
            "creation_date": profile.creation_date,
            "effective_date": profile.effective_date,
            "mcc": profile.mcc,
            "mnc": profile.mnc,
            "metadata": profile.metadata or {},
            "search_text": _search_text_doc(profile),
            "updated_at": now,
        }
        field_rows = [
            {
                "document_id": profile.document_id,
                "file_name": profile.file_name,
                "field_key": f.field_key,
                "field_value": f.field_value,
                "section_id": f.section_id,
                "section_title": f.section_title,
                "page": f.page,
                "table_id": f.table_id,
                "source_chunk_id": f.source_chunk_id,
                "confidence": f.confidence,
                "search_text": _search_text_field(f),
            }
            for f in profile.fields
        ]
        ep_rows = [
            {
                "document_id": profile.document_id,
                "file_name": profile.file_name,
                "role": ep.role,
                "node_type": ep.node_type,
                "node_id": ep.node_id,
                "fqdn": ep.fqdn,
                "ip": ep.ip,
                "ip_secondary": ep.ip_secondary,
                "port": ep.port,
                "protocol": ep.protocol,
                "gt_address": ep.gt_address,
                "vendor": ep.vendor,
                "section_id": ep.section_id,
                "page": ep.page,
                "extras": ep.extras or {},
                "search_text": _search_text_endpoint(ep),
            }
            for ep in profile.endpoints
        ]

        # Optional Voyage AI embeddings (MongoDB AI stack)
        if config.VOYAGE_API_KEY:
            texts = [doc["search_text"]] + [r["search_text"] for r in field_rows] + [
                r["search_text"] for r in ep_rows
            ]
            vectors = voyage_embed(texts)
            if vectors and len(vectors) == len(texts):
                doc["embedding"] = vectors[0]
                i = 1
                for r in field_rows:
                    r["embedding"] = vectors[i]
                    i += 1
                for r in ep_rows:
                    r["embedding"] = vectors[i]
                    i += 1

        self._docs.insert_one(doc)
        if field_rows:
            self._fields.insert_many(field_rows)
        if ep_rows:
            self._endpoints.insert_many(ep_rows)

    def delete_document(self, document_id: str) -> None:
        self._docs.delete_many({"document_id": document_id})
        self._fields.delete_many({"document_id": document_id})
        self._endpoints.delete_many({"document_id": document_id})

    def delete_by_file_name(self, file_name: str) -> None:
        for row in self._docs.find({"file_name": file_name}, {"document_id": 1}):
            self.delete_document(row["document_id"])

    def list_documents(self) -> list[str]:
        return sorted(self._docs.distinct("file_name"))

    def get_profile_summary(self, file_name: str) -> Optional[dict[str, Any]]:
        row = self._docs.find_one({"file_name": file_name})
        if not row:
            return None
        return {k: row.get(k) for k in (
            "document_id", "file_name", "title", "organisation_name", "country", "tadig",
            "network_type", "creation_date", "effective_date", "mcc", "mnc",
        )}

    def find_by_tadig(self, tadig: str) -> list[dict[str, Any]]:
        code = (tadig or "").upper().strip()
        if not code:
            return []
        return list(self._docs.find({"tadig": code}))

    def find_by_document_id(self, document_id: str) -> Optional[dict[str, Any]]:
        return self._docs.find_one({"document_id": document_id})

    def search_facts(
        self,
        query: str,
        file_name: Optional[str] = None,
        *,
        tadig: Optional[str] = None,
        document_id: Optional[str] = None,
        file_names: Optional[list[str]] = None,
        limit: int = 40,
    ) -> dict[str, Any]:
        tokens, _ = _query_tokens(query)
        filt: dict[str, Any] = {}
        if file_name:
            filt["file_name"] = file_name
        elif file_names:
            filt["file_name"] = {"$in": file_names}
        if tadig:
            filt["tadig"] = tadig.upper()
        if document_id:
            filt["document_id"] = document_id

        docs = list(self._docs.find(filt))
        fields = list(self._fields.find(filt))
        endpoints = list(self._endpoints.find(filt))

        scored_docs = self._score_documents(docs, tokens, file_name)
        scored_fields = self._score_fields(fields, tokens, file_name)
        scored_eps = self._score_endpoints(endpoints, tokens, file_name)

        # Semantic boost with Voyage embeddings when present
        if config.VOYAGE_API_KEY:
            q_vecs = voyage_embed([query])
            if q_vecs and q_vecs[0]:
                qv = q_vecs[0]
                self._apply_vector_boost(scored_fields, qv)
                self._apply_vector_boost(scored_eps, qv)
                scored_fields.sort(key=lambda x: x.get("_score", 0), reverse=True)
                scored_eps.sort(
                    key=lambda x: (x.get("_role_score", 0), x.get("_score", 0)),
                    reverse=True,
                )

        return {
            "documents": scored_docs[:5],
            "fields": scored_fields[:limit],
            "endpoints": scored_eps[:limit],
            "backend": self._backend,
            "tokens": tokens,
        }

    def facts_markdown(self, query: str, file_name: Optional[str] = None, limit: int = 40) -> str:
        data = self.search_facts(query, file_name=file_name, limit=limit)
        if not data["documents"] and not data["fields"] and not data["endpoints"]:
            return ""
        tokens, substantive = _query_tokens(query)
        endpoints, fields, meta_lines = _select_facts_for_query(data, tokens, substantive)

        lines = [f"### Structured facts ({data['backend']})"]
        for d in data["documents"][:2]:
            lines.append(f"- **Source document**: {d.get('file_name')}")
        for ml in meta_lines:
            lines.append(ml)

        if endpoints:
            lines.append("\n#### Matching endpoints / network elements")
            for ep in endpoints:
                bits = [
                    ep.get("role") or ep.get("node_type"),
                    f"GT={ep['gt_address']}" if ep.get("gt_address") else "",
                    f"FQDN={ep['fqdn']}" if ep.get("fqdn") else "",
                    f"IP={ep['ip']}" if ep.get("ip") else "",
                    f"IP2={ep['ip_secondary']}" if ep.get("ip_secondary") else "",
                    ep.get("protocol") or "",
                    f"Sec {ep['section_id']}" if ep.get("section_id") else "",
                    f"p.{ep['page']}" if ep.get("page") else "",
                ]
                lines.append(f"- {' | '.join(b for b in bits if b)} _({ep.get('file_name')})_")

        if fields:
            lines.append("\n#### Matching fields")
            for f in fields:
                sec = f" [Sec {f['section_id']}]" if f.get("section_id") else ""
                page = f" (p.{f['page']})" if f.get("page") else ""
                lines.append(
                    f"- **{f['field_key']}**{sec}{page} — {f['field_value']} "
                    f"_({f.get('file_name')})_"
                )
        return "\n".join(lines)

    # ---- scoring (same intelligence as former SQL store) ----

    def _score_documents(
        self, rows: list[dict], tokens: list[str], file_name: Optional[str]
    ) -> list[dict]:
        skip = {
            "_id", "embedding", "search_text", "metadata", "updated_at", "document_id",
            "file_name", "_score",
        }
        out = []
        for d in rows:
            if file_name and d.get("file_name") != file_name:
                continue
            meta_keys = {
                k for k, v in d.items()
                if k not in skip and not k.startswith("_")
                and isinstance(v, (str, int, float)) and str(v).strip()
            }
            score = 0.0
            for t in tokens:
                if t in meta_keys and d.get(t):
                    score += 4.0
                blob = " ".join(
                    str(v or "") for k, v in d.items() if k not in ("embedding", "_id")
                ).lower()
                if _word_in(t, blob) or t in blob:
                    score += 1.0
            if not tokens or score > 0 or (file_name and d.get("file_name") == file_name):
                d["_score"] = score
                out.append(d)
        out.sort(key=lambda x: x.get("_score", 0), reverse=True)
        return out

    def _score_fields(
        self, rows: list[dict], tokens: list[str], file_name: Optional[str]
    ) -> list[dict]:
        substantive = [t for t in tokens if t not in _GENERIC_QUERY_TOKENS]
        out = []
        for d in rows:
            if file_name and d.get("file_name") != file_name:
                continue
            score = 0.0
            key_hits = 0.0
            for t in tokens:
                ts = _field_token_score(t, d.get("field_key") or "", d.get("field_value") or "")
                if t in _GENERIC_QUERY_TOKENS:
                    score += min(ts, 0.2)
                else:
                    score += ts
                    if ts >= 5.0:
                        key_hits += 1
            d["_key_hits"] = key_hits
            if substantive and score < 1.0:
                continue
            if score > 0 or (file_name and not tokens):
                d["_score"] = score
                out.append(d)
        out.sort(key=lambda x: (x.get("_key_hits", 0), x.get("_score", 0)), reverse=True)
        return out

    def _score_endpoints(
        self, rows: list[dict], tokens: list[str], file_name: Optional[str]
    ) -> list[dict]:
        substantive = [t for t in tokens if t not in _GENERIC_QUERY_TOKENS]
        wants_addr = any(
            t in {"gt", "gts", "global", "title", "titles", "ip", "ips", "fqdn", "address"}
            for t in tokens
        )
        exact_tokens: set[str] = set()
        parsed: list[tuple[dict, list[str]]] = []
        for d in rows:
            if file_name and d.get("file_name") != file_name:
                continue
            parts = _role_parts(f"{d.get('role') or ''} {d.get('node_type') or ''}")
            parsed.append((d, parts))
            for t in substantive:
                if t in parts:
                    exact_tokens.add(t)

        out = []
        for d, parts in parsed:
            gt = (d.get("gt_address") or "").lower()
            ip = f"{d.get('ip') or ''} {d.get('ip_secondary') or ''}".lower()
            fqdn = (d.get("fqdn") or "").lower()
            protocol = (d.get("protocol") or "").lower()
            role_score = 0.0
            addr_score = 0.0
            for t in tokens:
                if t in _GENERIC_QUERY_TOKENS:
                    continue
                sc, kind = _token_role_match(t, parts)
                if kind == "sub" and t in exact_tokens:
                    sc = 0.0
                role_score += sc
                if t in gt:
                    addr_score += 3.0
                elif t in ip:
                    addr_score += 2.5
                elif t in protocol:
                    addr_score += 2.0
                elif len(t) >= 4 and t in fqdn:
                    addr_score += 1.0
            score = role_score * 10.0 + addr_score
            if wants_addr and d.get("gt_address") and role_score > 0:
                score += 1.0
            if substantive:
                if role_score <= 0 and addr_score <= 0:
                    continue
            elif wants_addr:
                if not (d.get("gt_address") or d.get("ip") or d.get("fqdn")):
                    continue
                score = max(score, 0.5)
            elif score <= 0:
                continue
            d["_score"] = score
            d["_role_score"] = role_score
            out.append(d)
        out.sort(key=lambda x: (x.get("_role_score", 0), x.get("_score", 0)), reverse=True)
        if any(float(e.get("_role_score") or 0) > 0 for e in out):
            out = [e for e in out if float(e.get("_role_score") or 0) > 0]
        return out

    @staticmethod
    def _apply_vector_boost(rows: list[dict], qv: list[float]) -> None:
        for row in rows:
            emb = row.get("embedding")
            if isinstance(emb, list) and emb:
                row["_score"] = float(row.get("_score") or 0) + cosine(qv, emb) * 4.0


_store: Optional[MongoStructuredStore] = None


def get_structured_store() -> MongoStructuredStore:
    """Preferred structured-store entrypoint (MongoDB)."""
    global _store
    if _store is None:
        _store = MongoStructuredStore()
    return _store
