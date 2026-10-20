"""PostgreSQL structured store for IR.21 fields (SQLite fallback)."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Optional

import config
from shared.ir21_schema import IR21Field, IR21Profile


# English function words — weak alone. Value-type words come from schema attrs below.
_STOP_QUERY_TOKENS = frozenset(
    {
        "list", "all", "of", "the", "and", "for", "what", "is", "are", "show", "give",
        "a", "an", "to", "in", "on", "with", "from", "by", "or", "any", "please",
    }
)

# Attribute names on stored facts — tokens derived from these are treated as value-type
# (weak alone), so queries focus on entity tokens rather than “list all GTs”.
_FACT_ATTR_NAMES = (
    "gt_address", "fqdn", "ip", "ip_secondary", "protocol", "role", "node_type",
    "field_key", "field_value", "section_id", "section_title", "page",
    "organisation_name", "network_type", "creation_date", "effective_date",
)


def _generic_query_tokens() -> frozenset[str]:
    out = set(_STOP_QUERY_TOKENS)
    for name in _FACT_ATTR_NAMES:
        parts = [p for p in re.split(r"[^a-z0-9]+", name.lower()) if len(p) >= 2]
        for p in parts:
            out.add(p)
            if not p.endswith("s"):
                out.add(p + "s")
    return frozenset(out)


_GENERIC_QUERY_TOKENS = _generic_query_tokens()


def _role_parts(text: str) -> list[str]:
    return [p for p in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(p) >= 2]


def _token_role_match(token: str, role_parts: list[str]) -> tuple[float, str]:
    """Exact / adjacent-swap / 1-substitution match against role acronym parts."""
    best_sub = (0.0, "")
    for part in role_parts:
        if token == part:
            return 6.0, "exact"
        if len(token) != len(part) or not (3 <= len(token) <= 6):
            continue
        for i in range(len(token) - 1):
            swapped = token[:i] + token[i + 1] + token[i] + token[i + 2 :]
            if swapped == part:
                return 5.5, "transpose"
        if sum(x != y for x, y in zip(token, part)) == 1:
            best_sub = (4.5, "sub")
    return best_sub


def _word_in(token: str, text: str) -> bool:
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", text or ""))


def _field_token_score(token: str, field_key: str, field_value: str) -> float:
    """Prefer whole-word hits in the field name over substring hits in long values."""
    fk = (field_key or "").lower()
    fv = (field_value or "").lower()
    if re.search(rf"\({re.escape(token)}\)", fk):
        return 6.5  # acronym in parentheses in the field name
    if _word_in(token, fk):
        return 5.0
    if token in fk:
        return 2.0
    if _word_in(token, fv):
        return 1.5
    if len(token) >= 4 and token in fv and len(fv) < 48:
        return 0.8
    if len(token) >= 4 and token in fv:
        return 0.25
    return 0.0


def _query_tokens(query: str) -> tuple[list[str], list[str]]:
    tokens = [t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 2]
    substantive = [t for t in tokens if t not in _GENERIC_QUERY_TOKENS]
    return tokens, substantive


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    title TEXT,
    organisation_name TEXT,
    country TEXT,
    tadig TEXT,
    network_type TEXT,
    creation_date TEXT,
    effective_date TEXT,
    mcc TEXT,
    mnc TEXT,
    metadata_json TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ir21_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT NOT NULL,
    file_name TEXT,
    field_key TEXT NOT NULL,
    field_value TEXT NOT NULL,
    section_id TEXT,
    section_title TEXT,
    page INTEGER,
    table_id TEXT,
    source_chunk_id TEXT,
    confidence REAL DEFAULT 1.0
);

CREATE TABLE IF NOT EXISTS ir21_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT NOT NULL,
    file_name TEXT,
    role TEXT,
    node_type TEXT,
    node_id TEXT,
    fqdn TEXT,
    ip TEXT,
    ip_secondary TEXT,
    port TEXT,
    protocol TEXT,
    gt_address TEXT,
    vendor TEXT,
    section_id TEXT,
    page INTEGER,
    extras_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_fields_doc ON ir21_fields(document_id);
CREATE INDEX IF NOT EXISTS idx_fields_key ON ir21_fields(field_key);
CREATE INDEX IF NOT EXISTS idx_fields_section ON ir21_fields(section_id);
CREATE INDEX IF NOT EXISTS idx_fields_value ON ir21_fields(field_value);
CREATE INDEX IF NOT EXISTS idx_ep_doc ON ir21_endpoints(document_id);
CREATE INDEX IF NOT EXISTS idx_ep_ip ON ir21_endpoints(ip);
CREATE INDEX IF NOT EXISTS idx_docs_tadig ON documents(tadig);
CREATE INDEX IF NOT EXISTS idx_docs_file ON documents(file_name);
"""


class StructuredStore:
    """SQL store for IR.21 structured facts. Prefers Postgres, falls back to SQLite."""

    def __init__(self) -> None:
        self._pg = None
        self._sqlite_path = Path(config.STRUCTURED_DB_PATH)
        self._backend = "sqlite"
        if config.POSTGRES_DSN:
            try:
                import psycopg
                self._pg = psycopg.connect(
                    config.POSTGRES_DSN,
                    autocommit=True,
                    connect_timeout=3,
                )
                self._backend = "postgres"
                self._init_postgres()
            except Exception as exc:
                print(f"[structured_store] Postgres unavailable ({exc}); using SQLite")
                self._pg = None
                self._backend = "sqlite"
        if self._backend == "sqlite":
            self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_sqlite()

    @property
    def backend(self) -> str:
        return self._backend

    def _init_sqlite(self) -> None:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.executescript(_SCHEMA_SQL)

    def _init_postgres(self) -> None:
        assert self._pg is not None
        # Adapt AUTOINCREMENT / types lightly
        sql = _SCHEMA_SQL.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        sql = sql.replace("TEXT", "TEXT")
        with self._pg.cursor() as cur:
            for stmt in filter(None, (s.strip() for s in sql.split(";"))):
                try:
                    cur.execute(stmt)
                except Exception:
                    pass

    def upsert_profile(self, profile: IR21Profile) -> None:
        self.delete_document(profile.document_id)
        meta = json.dumps(profile.metadata or {})
        if self._backend == "postgres":
            assert self._pg is not None
            with self._pg.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO documents(
                        document_id, file_name, title, organisation_name, country, tadig,
                        network_type, creation_date, effective_date, mcc, mnc, metadata_json
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        profile.document_id, profile.file_name, profile.title,
                        profile.organisation_name, profile.country, profile.tadig,
                        profile.network_type, profile.creation_date, profile.effective_date,
                        profile.mcc, profile.mnc, meta,
                    ),
                )
                for f in profile.fields:
                    cur.execute(
                        """
                        INSERT INTO ir21_fields(
                            document_id, file_name, field_key, field_value, section_id,
                            section_title, page, table_id, source_chunk_id, confidence
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            profile.document_id, profile.file_name, f.field_key, f.field_value,
                            f.section_id, f.section_title, f.page, f.table_id,
                            f.source_chunk_id, f.confidence,
                        ),
                    )
                for ep in profile.endpoints:
                    cur.execute(
                        """
                        INSERT INTO ir21_endpoints(
                            document_id, file_name, role, node_type, node_id, fqdn, ip,
                            ip_secondary, port, protocol, gt_address, vendor, section_id, page, extras_json
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            profile.document_id, profile.file_name, ep.role, ep.node_type, ep.node_id,
                            ep.fqdn, ep.ip, ep.ip_secondary, ep.port, ep.protocol, ep.gt_address,
                            ep.vendor, ep.section_id, ep.page, json.dumps(ep.extras or {}),
                        ),
                    )
            return

        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(
                """
                INSERT INTO documents(
                    document_id, file_name, title, organisation_name, country, tadig,
                    network_type, creation_date, effective_date, mcc, mnc, metadata_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    profile.document_id, profile.file_name, profile.title,
                    profile.organisation_name, profile.country, profile.tadig,
                    profile.network_type, profile.creation_date, profile.effective_date,
                    profile.mcc, profile.mnc, meta,
                ),
            )
            conn.executemany(
                """
                INSERT INTO ir21_fields(
                    document_id, file_name, field_key, field_value, section_id,
                    section_title, page, table_id, source_chunk_id, confidence
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        profile.document_id, profile.file_name, f.field_key, f.field_value,
                        f.section_id, f.section_title, f.page, f.table_id,
                        f.source_chunk_id, f.confidence,
                    )
                    for f in profile.fields
                ],
            )
            conn.executemany(
                """
                INSERT INTO ir21_endpoints(
                    document_id, file_name, role, node_type, node_id, fqdn, ip,
                    ip_secondary, port, protocol, gt_address, vendor, section_id, page, extras_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        profile.document_id, profile.file_name, ep.role, ep.node_type, ep.node_id,
                        ep.fqdn, ep.ip, ep.ip_secondary, ep.port, ep.protocol, ep.gt_address,
                        ep.vendor, ep.section_id, ep.page, json.dumps(ep.extras or {}),
                    )
                    for ep in profile.endpoints
                ],
            )
            conn.commit()

    def delete_document(self, document_id: str) -> None:
        if self._backend == "postgres":
            assert self._pg is not None
            with self._pg.cursor() as cur:
                cur.execute("DELETE FROM ir21_fields WHERE document_id=%s", (document_id,))
                cur.execute("DELETE FROM ir21_endpoints WHERE document_id=%s", (document_id,))
                cur.execute("DELETE FROM documents WHERE document_id=%s", (document_id,))
            return
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute("DELETE FROM ir21_fields WHERE document_id=?", (document_id,))
            conn.execute("DELETE FROM ir21_endpoints WHERE document_id=?", (document_id,))
            conn.execute("DELETE FROM documents WHERE document_id=?", (document_id,))
            conn.commit()

    def delete_by_file_name(self, file_name: str) -> None:
        rows = self._fetch_all("SELECT document_id FROM documents WHERE file_name = ?", (file_name,))
        for (doc_id,) in rows:
            self.delete_document(doc_id)

    def search_facts(
        self,
        query: str,
        file_name: Optional[str] = None,
        limit: int = 40,
    ) -> dict[str, Any]:
        """General keyword search over structured IR.21 docs/fields/endpoints."""
        tokens, _ = _query_tokens(query)

        section_hint = None
        m = re.search(r"section\s*(?:id)?\s*(\d{1,2})", query or "", re.I)
        if m:
            section_hint = m.group(1)

        docs = self._search_documents(tokens, file_name)
        fields = self._search_fields(tokens, file_name, section_hint, limit)
        endpoints = self._search_endpoints(tokens, file_name, limit)

        return {
            "documents": docs[:5],
            "fields": fields[:limit],
            "endpoints": endpoints[:limit],
            "backend": self._backend,
            "tokens": tokens,
        }

    def facts_markdown(self, query: str, file_name: Optional[str] = None, limit: int = 40) -> str:
        data = self.search_facts(query, file_name=file_name, limit=limit)
        if not data["documents"] and not data["fields"] and not data["endpoints"]:
            return ""

        tokens, substantive = _query_tokens(query)
        endpoints, fields, meta_lines = _select_facts_for_query(
            data, tokens, substantive
        )

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

    def get_profile_summary(self, file_name: str) -> Optional[dict[str, Any]]:
        rows = self._fetch_all(
            "SELECT document_id, file_name, title, organisation_name, country, tadig, "
            "network_type, creation_date, effective_date, mcc, mnc FROM documents WHERE file_name = ?",
            (file_name,),
        )
        if not rows:
            return None
        r = rows[0]
        keys = [
            "document_id", "file_name", "title", "organisation_name", "country", "tadig",
            "network_type", "creation_date", "effective_date", "mcc", "mnc",
        ]
        return dict(zip(keys, r))

    def list_documents(self) -> list[str]:
        rows = self._fetch_all("SELECT DISTINCT file_name FROM documents ORDER BY file_name", ())
        return [r[0] for r in rows if r[0]]

    # ---- internals ----

    def _ph(self) -> str:
        return "%s" if self._backend == "postgres" else "?"

    def _fetch_all(self, sql: str, params: tuple) -> list[tuple]:
        if self._backend == "postgres":
            sql = sql.replace("?", "%s")
            assert self._pg is not None
            with self._pg.cursor() as cur:
                cur.execute(sql, params)
                return list(cur.fetchall())
        with sqlite3.connect(self._sqlite_path) as conn:
            return list(conn.execute(sql, params).fetchall())

    def _search_documents(self, tokens: list[str], file_name: Optional[str]) -> list[dict]:
        rows = self._fetch_all(
            "SELECT document_id, file_name, title, organisation_name, country, tadig, "
            "network_type, creation_date, effective_date, mcc, mnc FROM documents",
            (),
        )
        keys = [
            "document_id", "file_name", "title", "organisation_name", "country", "tadig",
            "network_type", "creation_date", "effective_date", "mcc", "mnc",
        ]
        skip = {
            "_id", "embedding", "search_text", "metadata", "updated_at", "document_id",
            "file_name", "_score", "metadata_json",
        }
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            if file_name and d["file_name"] != file_name:
                continue
            meta_keys = {
                k for k, v in d.items()
                if k not in skip and isinstance(v, (str, int, float)) and str(v or "").strip()
            }
            score = 0.0
            for t in tokens:
                if t in meta_keys and d.get(t):
                    score += 4.0
                blob = " ".join(str(v or "") for v in d.values()).lower()
                if _word_in(t, blob) or t in blob:
                    score += 1.0
            if not tokens or score > 0 or (file_name and d["file_name"] == file_name):
                d["_score"] = score
                out.append(d)
        out.sort(key=lambda x: x.get("_score", 0), reverse=True)
        return out

    def _search_fields(
        self,
        tokens: list[str],
        file_name: Optional[str],
        section_hint: Optional[str],
        limit: int,
    ) -> list[dict]:
        sql = (
            "SELECT document_id, file_name, field_key, field_value, section_id, "
            "section_title, page FROM ir21_fields"
        )
        rows = self._fetch_all(sql, ())
        keys = ["document_id", "file_name", "field_key", "field_value", "section_id", "section_title", "page"]
        out = []
        substantive = [t for t in tokens if t not in _GENERIC_QUERY_TOKENS]
        for r in rows:
            d = dict(zip(keys, r))
            if file_name and d["file_name"] != file_name:
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
            if section_hint and str(d.get("section_id") or "") == section_hint:
                score += 2
            d["_key_hits"] = key_hits
            if substantive and score < 1.0 and not (file_name and not tokens):
                continue
            if score > 0 or (file_name and not tokens):
                d["_score"] = score
                out.append(d)
        out.sort(key=lambda x: (x.get("_key_hits", 0), x.get("_score", 0)), reverse=True)
        return out[:limit]

    def _search_endpoints(
        self,
        tokens: list[str],
        file_name: Optional[str],
        limit: int,
    ) -> list[dict]:
        rows = self._fetch_all(
            "SELECT document_id, file_name, role, node_type, node_id, fqdn, ip, ip_secondary, "
            "protocol, gt_address, section_id, page FROM ir21_endpoints",
            (),
        )
        keys = [
            "document_id", "file_name", "role", "node_type", "node_id", "fqdn", "ip",
            "ip_secondary", "protocol", "gt_address", "section_id", "page",
        ]
        substantive = [t for t in tokens if t not in _GENERIC_QUERY_TOKENS]
        wants_addr = any(
            t in {"gt", "gts", "global", "title", "titles", "ip", "ips", "fqdn", "address"}
            for t in tokens
        )

        # Tokens with an exact role hit somewhere — suppress 1-letter near-misses for those.
        exact_tokens: set[str] = set()
        parsed: list[tuple[dict, list[str]]] = []
        for r in rows:
            d = dict(zip(keys, r))
            if file_name and d["file_name"] != file_name:
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
            match_kinds: list[str] = []
            for t in tokens:
                if t in _GENERIC_QUERY_TOKENS:
                    continue
                sc, kind = _token_role_match(t, parts)
                if kind == "sub" and t in exact_tokens:
                    sc = 0.0
                    kind = ""
                if sc > 0:
                    role_score += sc
                    match_kinds.append(kind)
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
            d["_match_kinds"] = match_kinds
            out.append(d)

        out.sort(key=lambda x: (x.get("_role_score", 0), x.get("_score", 0)), reverse=True)
        if any(float(e.get("_role_score") or 0) > 0 for e in out):
            out = [e for e in out if float(e.get("_role_score") or 0) > 0]
        return out[:limit]


def _select_facts_for_query(
    data: dict,
    tokens: list[str],
    substantive: list[str],
) -> tuple[list[dict], list[dict], list[str]]:
    """
    Per-token coverage without domain hardcoding:
      - If a token hits a field *name* (or doc metadata column), keep that field/meta.
      - If a token hits an endpoint role (exact/transpose preferred over 1-letter sub), keep it.
      - Prefer exact field-name hits over fuzzy endpoint hits for the same token.
    """
    all_eps = list(data.get("endpoints") or [])
    all_fields = list(data.get("fields") or [])
    docs = list(data.get("documents") or [])
    # Metadata columns discovered from stored documents (not a fixed domain list)
    skip_meta = {
        "_id", "embedding", "search_text", "metadata", "updated_at", "document_id",
        "file_name", "_score", "_key_hits", "_role_score", "_match_kinds", "metadata_json",
    }
    meta_cols: set[str] = set()
    for d in docs:
        for k, v in d.items():
            if k in skip_meta or k.startswith("_"):
                continue
            if isinstance(v, (str, int, float)) and str(v).strip():
                meta_cols.add(k)

    # Tokens that strongly match a field key (whole word)
    field_key_tokens: set[str] = set()
    for f in all_fields:
        fk = f.get("field_key") or ""
        for t in substantive:
            if _field_token_score(t, fk, "") >= 5.0:
                field_key_tokens.add(t)

    # Also: token equals a populated metadata column name
    meta_lines: list[str] = []
    meta_tokens: set[str] = set()
    for d in docs[:3]:
        for col in meta_cols:
            if col in substantive and d.get(col):
                meta_tokens.add(col)
                meta_lines.append(
                    f"- **{col.upper()}** = {d.get(col)} _({d.get('file_name')})_"
                )
    # de-dupe meta lines
    seen_meta: set[str] = set()
    meta_out: list[str] = []
    for line in meta_lines:
        if line not in seen_meta:
            seen_meta.add(line)
            meta_out.append(line)
    meta_lines = meta_out[:6]
    field_key_tokens |= meta_tokens

    selected_eps: list[dict] = []
    selected_fields: list[dict] = []
    covered: set[str] = set()
    tentative_fields: dict[str, dict] = {}

    # 1) Strong field-name hits (parenthetical acronym / exact name word)
    for t in substantive:
        if t in meta_tokens:
            covered.add(t)
            field_key_tokens.add(t)
        best_f = None
        best_s = 0.0
        for f in all_fields:
            s = _field_token_score(t, f.get("field_key") or "", f.get("field_value") or "")
            if s > best_s:
                best_s = s
                best_f = f
        if best_f and best_s >= 6.5:
            if best_f not in selected_fields:
                selected_fields.append(best_f)
            covered.add(t)
            field_key_tokens.add(t)
        elif best_f and best_s >= 5.0:
            tentative_fields[t] = best_f
            field_key_tokens.add(t)

    # 2) Endpoints (exact/transpose; skip 1-letter fuzzy when a field-name already claims the token)
    for t in substantive:
        best_e = None
        best_s = 0.0
        for e in all_eps:
            parts = _role_parts(f"{e.get('role') or ''} {e.get('node_type') or ''}")
            sc, kind = _token_role_match(t, parts)
            if sc <= 0:
                continue
            if kind == "sub" and t in field_key_tokens:
                continue
            if sc > best_s:
                best_s = sc
                best_e = e
        if best_e and best_s >= 4.5:
            if best_e not in selected_eps:
                selected_eps.append(best_e)
            covered.add(t)

    # 3) Tentative field-name hits only if endpoint did not already cover the token
    for t, f in tentative_fields.items():
        if t in covered:
            continue
        if f not in selected_fields:
            selected_fields.append(f)
        covered.add(t)

    # 4) Weaker field hits for still-uncovered tokens
    for t in substantive:
        if t in covered:
            continue
        best_f = None
        best_s = 0.0
        for f in all_fields:
            s = _field_token_score(t, f.get("field_key") or "", f.get("field_value") or "")
            if s > best_s:
                best_s = s
                best_f = f
        if best_f and best_s >= 2.0:
            if best_f not in selected_fields:
                selected_fields.append(best_f)
            covered.add(t)

    selected_eps = sorted(
        selected_eps,
        key=lambda e: (e.get("_role_score", 0), e.get("_score", 0)),
        reverse=True,
    )[:6]
    selected_fields = selected_fields[:6]
    return selected_eps, selected_fields, meta_lines


_store: Optional["StructuredStore"] = None


def get_structured_store():
    """Deprecated entrypoint — delegates to MongoDB structured store."""
    from shared.mongo_store import get_structured_store as _mongo

    return _mongo()
