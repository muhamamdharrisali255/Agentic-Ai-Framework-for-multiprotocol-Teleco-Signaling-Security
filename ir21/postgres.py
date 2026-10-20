"""PostgreSQL storage and retrieval for the IR.21 relational model."""

from __future__ import annotations

import os
from dataclasses import fields as dataclass_fields
from typing import Any, Optional, Sequence

from ir21.records import Dataset

DSN = os.getenv(
    "IR21_POSTGRES_DSN",
    os.getenv("POSTGRES_DSN", "postgresql://signaling:signaling@localhost:5432/signaling_rag"),
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ir21_document (
    document_id       TEXT PRIMARY KEY,
    file_name         TEXT NOT NULL,
    tadig             TEXT,
    organisation_name TEXT,
    country_initials  TEXT,
    network_type      TEXT,
    presentation_name TEXT,
    abbreviated_mnn   TEXT,
    mcc               TEXT,
    mnc               TEXT,
    creation_date     TEXT,
    creation_time     TEXT,
    tadig_gen_schema  TEXT,
    raex_schema       TEXT,
    page_count        INTEGER,
    ingested_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ir21_section (
    id             SERIAL PRIMARY KEY,
    document_id    TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    section_id     TEXT,
    title          TEXT,
    obligation     TEXT,
    effective_date TEXT,
    page           INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_network_element (
    id            SERIAL PRIMARY KEY,
    document_id   TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    node_type     TEXT,
    node_id       TEXT,
    gt_address    TEXT,
    ip_address    TEXT,
    vendor        TEXT,
    sw_hw_version TEXT,
    dual_access   TEXT,
    location      TEXT,
    utc_offset    TEXT,
    section_id    TEXT,
    page          INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_map_version (
    id                  SERIAL PRIMARY KEY,
    document_id         TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    application_context TEXT,
    inbound_msc_vlr     TEXT,
    inbound_sgsn        TEXT,
    outbound            TEXT,
    comments            TEXT,
    section_id          TEXT,
    page                INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_camel_support (
    id           SERIAL PRIMARY KEY,
    document_id  TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    node         TEXT,
    direction    TEXT,
    cap_versions TEXT,
    section_id   TEXT,
    page         INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_camel_service (
    id               SERIAL PRIMARY KEY,
    document_id      TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    service_name     TEXT,
    service_key      TEXT,
    cap_version      TEXT,
    scp_gt_addresses TEXT,
    section_id       TEXT,
    page             INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_camel_feature (
    id            SERIAL PRIMARY KEY,
    document_id   TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    feature_group TEXT,
    feature_name  TEXT,
    supported     TEXT,
    planned_date  TEXT,
    section_id    TEXT,
    page          INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_number_range (
    id          SERIAL PRIMARY KEY,
    document_id TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    range_type  TEXT,
    cc          TEXT,
    ndc         TEXT,
    sn_start    TEXT,
    sn_stop     TEXT,
    section_id  TEXT,
    page        INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_diameter_endpoint (
    id           SERIAL PRIMARY KEY,
    document_id  TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    fqdn         TEXT,
    primary_ip   TEXT,
    secondary_ip TEXT,
    ipx_provider TEXT,
    realm        TEXT,
    architecture TEXT,
    section_id   TEXT,
    page         INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_roaming_flag (
    id          SERIAL PRIMARY KEY,
    document_id TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    category    TEXT,
    attribute   TEXT,
    value       TEXT,
    counterpart TEXT,
    section_id  TEXT,
    page        INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_ip_resource (
    id          SERIAL PRIMARY KEY,
    document_id TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    kind        TEXT,
    value       TEXT,
    label       TEXT,
    section_id  TEXT,
    page        INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_apn (
    id            SERIAL PRIMARY KEY,
    document_id   TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    list_type     TEXT,
    apn           TEXT,
    username      TEXT,
    password      TEXT,
    gateway_ip    TEXT,
    server_url    TEXT,
    dns_primary   TEXT,
    dns_secondary TEXT,
    section_id    TEXT,
    page          INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_contact (
    id          SERIAL PRIMARY KEY,
    document_id TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    category    TEXT,
    person_name TEXT,
    team_name   TEXT,
    job_title   TEXT,
    tel         TEXT,
    mobile      TEXT,
    fax         TEXT,
    email       TEXT,
    section_id  TEXT,
    page        INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_change_history (
    id           SERIAL PRIMARY KEY,
    document_id  TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    change_date  TEXT,
    section_id   TEXT,
    section_name TEXT,
    description  TEXT,
    page         INTEGER
);

CREATE TABLE IF NOT EXISTS ir21_unused_section (
    id           SERIAL PRIMARY KEY,
    document_id  TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    section_id   TEXT,
    section_name TEXT
);

CREATE TABLE IF NOT EXISTS ir21_fact (
    id            SERIAL PRIMARY KEY,
    document_id   TEXT REFERENCES ir21_document(document_id) ON DELETE CASCADE,
    field_key     TEXT,
    field_value   TEXT,
    section_id    TEXT,
    section_title TEXT,
    page          INTEGER
);

CREATE INDEX IF NOT EXISTS ix_ne_node_type ON ir21_network_element (lower(node_type));
CREATE INDEX IF NOT EXISTS ix_ne_gt ON ir21_network_element (gt_address);
CREATE INDEX IF NOT EXISTS ix_map_context ON ir21_map_version (lower(application_context));
CREATE INDEX IF NOT EXISTS ix_fact_key ON ir21_fact (lower(field_key));
CREATE INDEX IF NOT EXISTS ix_doc_tadig ON ir21_document (lower(tadig));
"""

# Dataset attribute -> table name. Every record table carries document_id.
TABLES: dict[str, str] = {
    "sections": "ir21_section",
    "network_elements": "ir21_network_element",
    "map_versions": "ir21_map_version",
    "camel_support": "ir21_camel_support",
    "camel_services": "ir21_camel_service",
    "camel_features": "ir21_camel_feature",
    "number_ranges": "ir21_number_range",
    "diameter_endpoints": "ir21_diameter_endpoint",
    "roaming_flags": "ir21_roaming_flag",
    "ip_resources": "ir21_ip_resource",
    "apns": "ir21_apn",
    "contacts": "ir21_contact",
    "change_history": "ir21_change_history",
    "unused_sections": "ir21_unused_section",
    "facts": "ir21_fact",
}


def connect(dsn: str | None = None):
    import psycopg

    return psycopg.connect(dsn or DSN, autocommit=True, connect_timeout=5)


def init_schema(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
    finally:
        if own:
            conn.close()


def load_dataset(data: Dataset, conn=None) -> dict[str, int]:
    """Replace all rows for this document with the freshly parsed dataset."""
    own = conn is None
    conn = conn or connect()
    try:
        init_schema(conn)
        doc = data.document
        with conn.cursor() as cur:
            cur.execute("DELETE FROM ir21_document WHERE document_id = %s", (doc.document_id,))
            cur.execute("DELETE FROM ir21_document WHERE file_name = %s", (doc.file_name,))
            doc_cols = [f.name for f in dataclass_fields(doc)]
            cur.execute(
                f"INSERT INTO ir21_document ({', '.join(doc_cols)}) "
                f"VALUES ({', '.join(['%s'] * len(doc_cols))})",
                tuple(getattr(doc, c) for c in doc_cols),
            )

            for attr, table in TABLES.items():
                rows = getattr(data, attr)
                if not rows:
                    continue
                cols = [f.name for f in dataclass_fields(rows[0])]
                placeholders = ", ".join(["%s"] * (len(cols) + 1))
                cur.executemany(
                    f"INSERT INTO {table} (document_id, {', '.join(cols)}) "
                    f"VALUES ({placeholders})",
                    [tuple([doc.document_id] + [getattr(r, c) for c in cols]) for r in rows],
                )
        return data.counts()
    finally:
        if own:
            conn.close()


def delete_document(file_name: str, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM ir21_document WHERE file_name = %s", (file_name,))
    finally:
        if own:
            conn.close()


def query(sql: str, params: Sequence[Any] = (), conn=None) -> list[dict[str, Any]]:
    """Run a read-only statement and return rows as dictionaries."""
    own = conn is None
    conn = conn or connect()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            if cur.description is None:
                return []
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    finally:
        if own:
            conn.close()


def list_documents(conn=None) -> list[dict[str, Any]]:
    return query(
        "SELECT document_id, file_name, tadig, organisation_name, country_initials, "
        "mcc, mnc, creation_date FROM ir21_document ORDER BY tadig",
        conn=conn,
    )


def table_counts(conn=None) -> dict[str, int]:
    out: dict[str, int] = {}
    for table in ["ir21_document", *TABLES.values()]:
        rows = query(f"SELECT count(*) AS n FROM {table}", conn=conn)
        out[table] = int(rows[0]["n"]) if rows else 0
    return out


def is_available() -> bool:
    try:
        conn = connect()
        conn.close()
        return True
    except Exception:
        return False
