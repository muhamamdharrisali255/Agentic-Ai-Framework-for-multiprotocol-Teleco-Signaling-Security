"""Neo4j ontology graph — operators, elements, events, attack patterns (§5).

Falls back to PostgreSQL relational reads when Neo4j is unavailable so the
graph specialist still returns structured facts.
"""

from __future__ import annotations

from typing import Any, Optional

import config
from app.ontology.queries import TEMPLATES, select_template


_CONSTRAINTS = [
    "CREATE CONSTRAINT operator_id IF NOT EXISTS FOR (o:Operator) REQUIRE o.network_id IS UNIQUE",
    "CREATE CONSTRAINT ne_id IF NOT EXISTS FOR (n:NetworkElement) REQUIRE n.network_element_id IS UNIQUE",
    "CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:SignalingEvent) REQUIRE e.event_id IS UNIQUE",
    "CREATE CONSTRAINT attack_id IF NOT EXISTS FOR (a:AttackPattern) REQUIRE a.attack_pattern_id IS UNIQUE",
    "CREATE CONSTRAINT rule_id IF NOT EXISTS FOR (r:DetectionRule) REQUIRE r.detection_rule_id IS UNIQUE",
    "CREATE INDEX subscriber_imsi IF NOT EXISTS FOR (s:Subscriber) ON (s.imsi)",
    "CREATE INDEX event_time IF NOT EXISTS FOR (e:SignalingEvent) ON (e.event_time)",
]


class OntologyGraphStore:
    def __init__(self) -> None:
        self._driver = None
        self._backend = "postgres"
        if getattr(config, "NEO4J_URI", None):
            try:
                from neo4j import GraphDatabase

                self._driver = GraphDatabase.driver(
                    config.NEO4J_URI,
                    auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
                    connection_timeout=5.0,
                )
                self._driver.verify_connectivity()
                self._backend = "neo4j"
                self.ensure_schema()
            except Exception as exc:
                print(f"[ontology] Neo4j unavailable ({exc}); using Postgres fallback")
                if self._driver is not None:
                    try:
                        self._driver.close()
                    except Exception:
                        pass
                self._driver = None
                self._backend = "postgres"

    @property
    def backend(self) -> str:
        return self._backend

    def is_available(self) -> bool:
        return self._backend == "neo4j" and self._driver is not None

    def ensure_schema(self) -> None:
        if not self.is_available():
            return
        assert self._driver is not None
        with self._driver.session() as session:
            for stmt in _CONSTRAINTS:
                session.run(stmt)

    def run_cypher(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        if not self.is_available():
            return []
        assert self._driver is not None
        with self._driver.session() as session:
            result = session.run(cypher, **(params or {}))
            return [dict(record) for record in result]

    def query_for_question(self, query: str, agent_ctx: Any = None) -> dict[str, Any]:
        template_name, params = select_template(query, agent_ctx)
        template = TEMPLATES[template_name]
        rows: list[dict[str, Any]] = []
        source = self._backend
        if self.is_available():
            try:
                rows = self.run_cypher(template["cypher"], params)
            except Exception as exc:
                return {
                    "template": template_name,
                    "params": params,
                    "rows": [],
                    "ok": False,
                    "empty": True,
                    "error": str(exc),
                    "backend": self._backend,
                    "status": "ERROR",
                }
        if not rows:
            rows = _postgres_fallback(template_name, params)
            source = "postgres_fallback" if rows else self._backend
        status = "OK" if rows else "NOT_FOUND"
        return {
            "template": template_name,
            "description": template.get("description", ""),
            "params": params,
            "rows": rows,
            "ok": True,
            "empty": not rows,
            "backend": source,
            "status": status,
        }

    def write_merge(self, cypher: str, params: dict[str, Any] | None = None) -> None:
        if not self.is_available():
            return
        assert self._driver is not None
        with self._driver.session() as session:
            session.run(cypher, **(params or {}))


_store: Optional[OntologyGraphStore] = None


def get_ontology_store() -> OntologyGraphStore:
    global _store
    if _store is None:
        _store = OntologyGraphStore()
    return _store


def _postgres_fallback(template: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Structured facts from the 16-table model when Neo4j is down."""
    try:
        from app.database import postgres
    except Exception:
        return []
    if not postgres.is_available():
        return []
    try:
        if template == "authorize_identity":
            return _pg_authorize(params)
        if template == "ulr_legitimacy":
            return _pg_ulr(params)
        if template == "sequence_check":
            return _pg_sequence(params)
        if template == "attack_detection_rule":
            return _pg_attack_rules(params)
        if template == "roaming_partner":
            return _pg_roaming(params)
    except Exception:
        return []
    return []


def _pg_authorize(params: dict[str, Any]) -> list[dict[str, Any]]:
    from app.database import postgres

    rows = []
    gt = params.get("gt") or ""
    host = params.get("host") or ""
    realm = params.get("realm") or ""
    if gt:
        rows = postgres.fetch_all(
            """
            SELECT p.network_id, p.operator_name, p.agreement_status,
                   g.global_title, g.authorized AS gt_authorized
            FROM ss7_global_title g
            JOIN plmn p ON p.network_id = g.network_id
            WHERE g.global_title = %s
            """,
            (gt,),
        )
    elif host:
        rows = postgres.fetch_all(
            """
            SELECT p.network_id, p.operator_name, p.agreement_status,
                   h.host_name, h.authorized AS host_authorized, h.realm
            FROM diameter_host h
            JOIN plmn p ON p.network_id = h.network_id
            WHERE lower(h.host_name) LIKE lower(%s)
            """,
            (f"%{host}%",),
        )
    elif realm:
        rows = postgres.fetch_all(
            """
            SELECT p.network_id, p.operator_name, p.agreement_status,
                   r.realm, r.authorized AS realm_authorized
            FROM diameter_realm r
            JOIN plmn p ON p.network_id = r.network_id
            WHERE lower(r.realm) LIKE lower(%s)
            """,
            (f"%{realm}%",),
        )
    else:
        op = params.get("operator") or params.get("partner") or ""
        if not op:
            return []
        rows = postgres.fetch_all(
            """
            SELECT network_id, operator_name, agreement_status, role, tadig
            FROM plmn
            WHERE lower(operator_name) LIKE lower(%s) OR network_id = %s OR tadig = %s
            """,
            (f"%{op}%", op, op),
        )
    return [dict(r) for r in rows]


def _pg_ulr(params: dict[str, Any]) -> list[dict[str, Any]]:
    from app.database import postgres

    imsi = params.get("imsi") or ""
    if not imsi:
        return []
    sub = postgres.fetch_one("SELECT * FROM subscriber_state WHERE imsi = %s", (imsi,))
    rel = postgres.fetch_all(
        """
        SELECT r.*, e1.message_name AS from_msg, e2.message_name AS to_msg
        FROM signaling_relationship r
        JOIN signaling_event e1 ON e1.event_id = r.event_1_id
        JOIN signaling_event e2 ON e2.event_id = r.event_2_id
        WHERE r.imsi = %s
        ORDER BY e1.event_time
        LIMIT 10
        """,
        (imsi,),
    )
    out = []
    for r in rel:
        out.append({
            "imsi": imsi,
            "registration_state": (sub or {}).get("registration_state"),
            "auth_state": (sub or {}).get("auth_state"),
            "from_msg": r.get("from_msg"),
            "to_msg": r.get("to_msg"),
            "time_delta_sec": float(r["time_delta_sec"]) if r.get("time_delta_sec") is not None else None,
            "expected": r.get("expected"),
            "risk": r.get("risk"),
        })
    if not out and sub:
        out.append({
            "imsi": imsi,
            "registration_state": sub.get("registration_state"),
            "auth_state": sub.get("auth_state"),
        })
    return out


def _pg_sequence(params: dict[str, Any]) -> list[dict[str, Any]]:
    from app.database import postgres

    imsi = params.get("imsi") or ""
    if not imsi:
        return []
    rows = postgres.fetch_all(
        """
        SELECT e1.message_name AS from_msg, e2.message_name AS to_msg,
               r.time_delta_sec, r.expected, r.risk,
               r.event_1_id, r.event_2_id
        FROM signaling_relationship r
        JOIN signaling_event e1 ON e1.event_id = r.event_1_id
        JOIN signaling_event e2 ON e2.event_id = r.event_2_id
        WHERE r.imsi = %s
        ORDER BY e1.event_time
        LIMIT 30
        """,
        (imsi,),
    )
    return [dict(r) for r in rows]


def _pg_attack_rules(params: dict[str, Any]) -> list[dict[str, Any]]:
    from app.database import postgres

    pattern = params.get("pattern_id") or ""
    rule = params.get("rule_id") or ""
    sql = """
        SELECT ap.attack_pattern_id, ap.attack_name, ap.category, ap.severity AS attack_severity,
               dr.detection_rule_id, dr.rule_name, dr.action, dr.confidence, dr.status,
               dr.suricata_text
        FROM attack_pattern ap
        LEFT JOIN detection_rule dr ON dr.attack_pattern_id = ap.attack_pattern_id
        WHERE 1=1
    """
    args: list[Any] = []
    if pattern:
        sql += " AND (ap.attack_pattern_id = %s OR lower(ap.attack_name) LIKE lower(%s))"
        args.extend([pattern, f"%{pattern}%"])
    if rule:
        sql += " AND (dr.detection_rule_id = %s OR lower(dr.rule_name) LIKE lower(%s))"
        args.extend([rule, f"%{rule}%"])
    sql += " LIMIT 20"
    return [dict(r) for r in postgres.fetch_all(sql, tuple(args))]


def _pg_roaming(params: dict[str, Any]) -> list[dict[str, Any]]:
    from app.database import postgres

    partner = params.get("partner") or params.get("operator") or ""
    if partner:
        rows = postgres.fetch_all(
            """
            SELECT network_id AS partner_id, operator_name AS partner_name,
                   agreement_status, role, supported_roaming_direction AS direction
            FROM plmn
            WHERE role = 'PARTNER'
              AND (lower(operator_name) LIKE lower(%s) OR network_id = %s OR tadig = %s)
            """,
            (f"%{partner}%", partner, partner),
        )
    else:
        rows = postgres.fetch_all(
            """
            SELECT network_id AS partner_id, operator_name AS partner_name,
                   agreement_status, role, supported_roaming_direction AS direction
            FROM plmn WHERE role = 'PARTNER' LIMIT 20
            """
        )
    return [dict(r) for r in rows]
