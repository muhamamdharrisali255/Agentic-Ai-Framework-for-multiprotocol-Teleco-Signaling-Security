"""Structured retrieval over the IR.21 relational store.

Table selection is driven by the schema and by the values actually present in
the database rather than by a fixed keyword list: the router matches query
tokens against table labels, column names, and the distinct values of each
table's identifying columns. Adding a document with new node types or new
section vocabulary therefore improves routing with no code change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Optional

from ir21 import postgres as pg


@dataclass(frozen=True)
class TableSpec:
    table: str
    label: str
    #: Columns whose distinct values identify a row (matched against the query).
    key_columns: tuple[str, ...]
    #: Columns rendered in the evidence table, in order.
    display_columns: tuple[str, ...]
    #: Extra words that describe the table's subject matter.
    topic: tuple[str, ...] = ()
    order_by: str = ""


CATALOG: tuple[TableSpec, ...] = (
    TableSpec(
        table="ir21_network_element",
        label="Network elements",
        key_columns=("node_type", "node_id", "vendor"),
        display_columns=(
            "node_type", "node_id", "gt_address", "ip_address", "vendor", "utc_offset", "page",
        ),
        topic=("global title", "gt", "gts", "node", "element", "address", "vendor", "hlr", "network", "sgsn", "hlr", "hss", "smsc"),
        order_by="node_type, gt_address",
    ),
    TableSpec(
        table="ir21_camel_support",
        label="CAMEL CAP version support",
        key_columns=("node", "direction", "cap_versions"),
        display_columns=("node", "direction", "cap_versions", "section_id", "page"),
        topic=("camel", "cap", "version", "inbound", "outbound", "gsmssf"),
        order_by="direction",
    ),
    TableSpec(
        table="ir21_camel_service",
        label="CAMEL services",
        key_columns=("service_name", "cap_version"),
        display_columns=("service_name", "service_key", "cap_version", "scp_gt_addresses", "page"),
        topic=("camel", "service", "scp", "prepaid", "postpaid"),
    ),
    TableSpec(
        table="ir21_camel_feature",
        label="CAMEL phase 4 features",
        key_columns=("feature_group", "feature_name", "supported"),
        display_columns=("feature_group", "feature_name", "supported", "planned_date", "page"),
        topic=("camel", "csi", "phase", "feature", "functionality"),
    ),
    TableSpec(
        table="ir21_map_version",
        label="MAP application contexts",
        key_columns=("application_context", "inbound_msc_vlr", "inbound_sgsn", "outbound"),
        display_columns=(
            "application_context", "inbound_msc_vlr", "inbound_sgsn", "outbound", "page",
        ),
        topic=("map", "application", "context", "roaming", "interworking", "version"),
        order_by="application_context",
    ),
    TableSpec(
        table="ir21_number_range",
        label="Number ranges",
        key_columns=("range_type", "cc", "ndc"),
        display_columns=("range_type", "cc", "ndc", "sn_start", "sn_stop", "page"),
        topic=("msisdn", "number", "range", "ndc", "routing", "portability", "msrn", "series"),
        order_by="range_type, ndc",
    ),
    TableSpec(
        table="ir21_diameter_endpoint",
        label="Diameter edge agents",
        key_columns=("fqdn", "ipx_provider", "realm"),
        display_columns=(
            "fqdn", "primary_ip", "secondary_ip", "ipx_provider", "realm", "architecture", "page",
        ),
        topic=("diameter", "dea", "edge", "agent", "fqdn", "realm", "ipx", "lte", "epc"),
    ),
    TableSpec(
        table="ir21_roaming_flag",
        label="Roaming interface capabilities",
        key_columns=("category", "attribute", "value"),
        display_columns=("category", "attribute", "value", "counterpart", "page"),
        topic=("s6a", "s6d", "s8", "s9", "iwf", "sms", "scenario", "qci", "supported", "lte"),
    ),
    TableSpec(
        table="ir21_ip_resource",
        label="IP, DNS, ASN and GRX resources",
        key_columns=("kind", "value", "label"),
        display_columns=("kind", "value", "label", "page"),
        topic=("ip", "backbone", "dns", "asn", "grx", "provider", "range"),
    ),
    TableSpec(
        table="ir21_apn",
        label="APN configuration",
        key_columns=("list_type", "apn"),
        display_columns=("list_type", "apn", "username", "gateway_ip", "server_url", "page"),
        topic=("apn", "gprs", "packet", "data", "wap", "mms"),
    ),
    TableSpec(
        table="ir21_contact",
        label="Contacts",
        key_columns=("category", "person_name", "team_name", "job_title", "email"),
        display_columns=("category", "person_name", "team_name", "tel", "mobile", "email", "page"),
        topic=("contact", "escalation", "troubleshooting", "coordinator", "email", "phone"),
    ),
    TableSpec(
        table="ir21_change_history",
        label="Change history",
        key_columns=("section_name", "description", "change_date"),
        display_columns=("change_date", "section_id", "section_name", "description", "page"),
        topic=("history of changes", "change history", "updated", "added", "removed"),
        order_by="change_date DESC",
    ),
    TableSpec(
        table="ir21_unused_section",
        label="Sections not in use",
        key_columns=("section_name",),
        display_columns=("section_id", "section_name"),
        topic=("not in use", "unused", "absent", "section"),
    ),
    TableSpec(
        table="ir21_section",
        label="Document sections",
        key_columns=("title", "section_id"),
        display_columns=("section_id", "title", "obligation", "effective_date", "page"),
        topic=("section", "effective", "mandatory", "optional", "conditional"),
    ),
    TableSpec(
        table="ir21_fact",
        label="Other documented values",
        key_columns=("field_key", "field_value", "section_title"),
        display_columns=("field_key", "field_value", "section_title", "page"),
        topic=("value", "field", "setting", "authentication", "cipher", "qos"),
    ),
)

_BY_TABLE = {spec.table: spec for spec in CATALOG}

_STOPWORDS = frozenset(
    """
    a an and are all any as at be by can do does for from get give has have how in is it its
    list me my of on or please show that the their there these this to us use used using what
    when where which who why with your
    """.split()
)


@dataclass
class Hit:
    spec: TableSpec
    sql: str
    params: list[Any]
    rows: list[dict[str, Any]]
    score: float
    matched: list[str] = field(default_factory=list)


def _tokens(query: str) -> list[str]:
    raw = re.findall(r"[A-Za-z0-9][A-Za-z0-9/._-]*", (query or "").lower())
    out: list[str] = []
    for tok in raw:
        tok = tok.strip("._-/")
        if len(tok) < 2 or tok in _STOPWORDS:
            continue
        out.append(tok)
        if tok.endswith("s") and len(tok) >= 3 and not tok.endswith("ss"):
            out.append(tok[:-1])
    return list(dict.fromkeys(out))


@lru_cache(maxsize=1)
def _vocabulary() -> dict[str, dict[str, set[str]]]:
    """Distinct key-column values per table, lowercased, for data-driven routing."""
    vocab: dict[str, dict[str, set[str]]] = {}
    for spec in CATALOG:
        columns: dict[str, set[str]] = {}
        for col in spec.key_columns:
            try:
                rows = pg.query(
                    f"SELECT DISTINCT {col} AS v FROM {spec.table} "
                    f"WHERE {col} IS NOT NULL AND {col} <> '' LIMIT 400"
                )
            except Exception:
                rows = []
            values = set()
            for row in rows:
                value = str(row["v"]).lower()
                values.add(value)
                for part in re.split(r"[^a-z0-9]+", value):
                    if len(part) >= 2:
                        values.add(part)
            columns[col] = values
        vocab[spec.table] = columns
    return vocab


def refresh_vocabulary() -> None:
    _vocabulary.cache_clear()
    _documents.cache_clear()


def _label_words(spec: TableSpec) -> set[str]:
    words = set(re.split(r"[^a-z0-9]+", spec.label.lower()))
    words |= {w for t in spec.topic for w in t.split()}
    return {w for w in words if len(w) >= 2}


def _score_table(spec: TableSpec, tokens: list[str]) -> tuple[float, dict[str, set[str]]]:
    """Score a table and collect which key column each token matched."""
    vocab = _vocabulary().get(spec.table, {})
    labels = _label_words(spec)
    score = 0.0
    matches: dict[str, set[str]] = {}
    for tok in tokens:
        if tok in labels:
            score += 1.5
        for col, values in vocab.items():
            if tok in values:
                score += 3.0
                if tok not in _SQL_SKIP:
                    matches.setdefault(col, set()).add(tok)
                break
    return score, matches


def _operator_ids(tokens: list[str]) -> list[str]:
    """Document ids whose operator identity is named in the question."""
    ids: list[str] = []
    for d in _documents():
        blob = " ".join(
            str(d.get(k) or "")
            for k in (
                "tadig",
                "organisation_name",
                "presentation_name",
                "abbreviated_mnn",
                "country_initials",
            )
        ).lower()
        parts = {p for p in re.split(r"[^a-z0-9]+", blob) if len(p) >= 3}
        if any(t in parts or t in blob for t in tokens if len(t) >= 3):
            ids.append(str(d["document_id"]))
    return ids


def _build_sql(
    spec: TableSpec,
    matches: dict[str, set[str]],
    limit: int,
    document_ids: list[str] | None = None,
) -> tuple[str, list[Any]]:
    cols = ", ".join(f"t.{c}" for c in spec.display_columns)
    cols = f"d.tadig, d.presentation_name, d.organisation_name, {cols}"
    where: list[str] = []
    params: list[Any] = []
    if document_ids:
        where.append("t.document_id = ANY(%s)")
        params.append(document_ids)
    for col, toks in matches.items():
        clauses = []
        for tok in sorted(toks):
            clauses.append(f"t.{col} ILIKE %s")
            params.append(f"%{tok}%")
        where.append("(" + " OR ".join(clauses) + ")")
    sql = (
        f"SELECT {cols} FROM {spec.table} t "
        f"JOIN ir21_document d ON d.document_id = t.document_id"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    if spec.order_by:
        sql += " ORDER BY " + ", ".join(f"t.{c.strip()}" for c in spec.order_by.split(","))
    sql += f" LIMIT {limit}"
    return sql, params


_SQL_SKIP = frozenset(
    """
    gt gts node element elements address addresses version versions value values
    network global title vendor page section information support supported
    """.split()
)
_HISTORY_TERMS = frozenset({"history", "change", "updated", "added", "removed", "when"})
_NOISY_TABLES = frozenset({"ir21_contact", "ir21_fact", "ir21_change_history", "ir21_unused_section"})


def search(query: str, max_tables: int = 3, limit: int = 40) -> list[Hit]:
    """Route a question to IR.21 tables and run the generated SQL."""
    tokens = _tokens(query)
    if not tokens:
        return []

    document_ids = _operator_ids(tokens)
    scored = []
    for spec in CATALOG:
        if spec.table == "ir21_change_history" and not (set(tokens) & _HISTORY_TERMS):
            continue
        if spec.table in _NOISY_TABLES:
            labels = _label_words(spec)
            if not any(t in labels for t in tokens):
                continue
        score, matches = _score_table(spec, tokens)
        if score <= 0:
            continue
        # A table matched only by its label is a weak candidate on its own.
        if not matches and score < 3.0:
            continue
        scored.append((score, spec, matches))

    scored.sort(key=lambda item: item[0], reverse=True)
    if scored:
        top = scored[0][0]
        scored = [item for item in scored if item[0] >= max(top * 0.45, 3.0) or item[1].table == scored[0][1].table]
    hits: list[Hit] = []
    for score, spec, matches in scored[:max_tables]:
        sql, params = _build_sql(spec, matches, limit, document_ids or None)
        try:
            rows = pg.query(sql, params)
        except Exception:
            continue
        if not rows:
            continue
        hits.append(
            Hit(
                spec=spec,
                sql=sql,
                params=params,
                rows=rows,
                score=score,
                matched=sorted({t for toks in matches.values() for t in toks}),
            )
        )
    return hits


@lru_cache(maxsize=1)
def _documents() -> list[dict[str, Any]]:
    try:
        return pg.query(
            "SELECT document_id, file_name, tadig, organisation_name, country_initials, "
            "presentation_name, abbreviated_mnn, mcc, mnc, creation_date "
            "FROM ir21_document ORDER BY tadig"
        )
    except Exception:
        return []


def operator_label() -> str:
    """Short operator identity, e.g. ``Zain-Kuwait (KWTMT)``.

    The trading name lives in ``presentation_name``; the legal name in
    ``organisation_name`` often differs, which is why a question about "Zain
    Kuwait" must not be matched against the legal name alone.
    """
    docs = _documents()
    if not docs:
        return ""
    d = docs[0]
    name = d.get("presentation_name") or d.get("organisation_name") or d.get("file_name")
    return f"{name} ({d['tadig']})" if d.get("tadig") else str(name)


def _document_header() -> str:
    parts = []
    for d in _documents():
        trading = d.get("presentation_name") or d.get("abbreviated_mnn")
        legal = d.get("organisation_name")
        label = trading or legal or d.get("file_name")
        if trading and legal and trading != legal:
            label = f"{trading} ({legal})"
        bits = [f"**{label}**"]
        if d.get("tadig"):
            bits.append(f"TADIG {d['tadig']}")
        if d.get("country_initials"):
            bits.append(f"country {d['country_initials']}")
        if d.get("mcc") and d.get("mnc"):
            bits.append(f"MCC/MNC {d['mcc']}/{d['mnc']}")
        if d.get("creation_date"):
            bits.append(f"issued {d['creation_date']}")
        parts.append(" · ".join(bits))
    return "; ".join(parts)


def evidence_markdown(query: str, hits: Optional[list[Hit]] = None) -> str:
    """Render structured hits as evidence the answer model can cite."""
    hits = search(query) if hits is None else hits
    if not hits:
        return ""

    header_docs = []
    seen = set()
    for hit in hits:
        for row in hit.rows:
            did = row.get("tadig") or row.get("document_id")
            if did and did not in seen:
                seen.add(did)
                header_docs.append(row)
    if header_docs:
        parts = []
        for d in header_docs:
            trading = d.get("presentation_name") or d.get("abbreviated_mnn")
            legal = d.get("organisation_name")
            tadig = d.get("tadig")
            label = trading or legal or tadig
            if trading and legal and trading != legal:
                label = f"{trading} ({legal})"
            bits = [f"**{label}**"]
            if tadig:
                bits.append(f"TADIG {tadig}")
            parts.append(" · ".join(bits))
        header = "; ".join(parts)
    else:
        header = _document_header()
    lines = ["### Structured evidence — IR.21 (PostgreSQL)"]
    if header:
        lines.append(f"Operator record: {header}")

    for hit in hits:
        cols = list(hit.spec.display_columns)
        if any(r.get("tadig") for r in hit.rows):
            cols = ["tadig"] + [c for c in cols if c != "tadig"]
        lines.append("")
        lines.append(f"#### {hit.spec.label} ({len(hit.rows)} row(s))")
        lines.append(f"Query: `{hit.sql}`")
        lines.append("")
        lines.append("| " + " | ".join(c.replace("_", " ") for c in cols) + " |")
        lines.append("| " + " | ".join("---" for _ in cols) + " |")
        for row in hit.rows:
            cells = [str(row.get(c, "") or "").replace("|", "/") for c in cols]
            lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def structured_evidence(query: str) -> dict[str, Any]:
    """Machine-readable structured evidence for the evidence builder."""
    hits = search(query)
    return {
        "backend": "postgresql",
        "documents": pg.list_documents(),
        "hits": [
            {
                "table": h.spec.table,
                "label": h.spec.label,
                "sql": h.sql,
                "params": h.params,
                "matched_terms": h.matched,
                "row_count": len(h.rows),
                "rows": h.rows,
            }
            for h in hits
        ],
        "markdown": evidence_markdown(query, hits),
    }
