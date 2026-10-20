"""Mirror PostgreSQL ontology tables into Neo4j (§5.3)."""

from __future__ import annotations

from typing import Any

from app.database import postgres
from app.ontology.graph_store import get_ontology_store


def mirror_all() -> dict[str, Any]:
    """Full config + security + recent runtime window → Neo4j."""
    store = get_ontology_store()
    if not store.is_available():
        return {"ok": False, "backend": store.backend, "mirrored": {}}
    store.ensure_schema()
    counts: dict[str, int] = {}
    counts["operators"] = _mirror_operators()
    counts["network_elements"] = _mirror_network_elements()
    counts["diameter"] = _mirror_diameter()
    counts["ss7"] = _mirror_ss7()
    counts["gtp"] = _mirror_gtp()
    counts["roaming"] = _mirror_roaming_edges()
    counts["subscribers"] = _mirror_subscribers()
    counts["events"] = _mirror_events(hours=72)
    counts["relationships"] = _mirror_relationships()
    counts["attack_patterns"] = _mirror_attack_patterns()
    counts["detection_rules"] = _mirror_detection_rules()
    return {"ok": True, "backend": "neo4j", "mirrored": counts}


def _mirror_operators() -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all("SELECT * FROM plmn")
    for row in rows:
        store.write_merge(
            """
            MERGE (o:Operator {network_id: $network_id})
            SET o.operator_name = $operator_name, o.mcc = $mcc, o.mnc = $mnc,
                o.plmn_id = $plmn_id, o.tadig = $tadig, o.role = $role,
                o.agreement_status = $agreement_status,
                o.supported_roaming_direction = $supported_roaming_direction
            """,
            dict(row),
        )
    return len(rows)


def _mirror_network_elements() -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all("SELECT * FROM network_element")
    for row in rows:
        store.write_merge(
            """
            MERGE (n:NetworkElement {network_element_id: $network_element_id})
            SET n.element_name = $element_name, n.element_type = $element_type,
                n.protocol = $protocol, n.ip_address = $ip_address, n.status = $status,
                n.gt = $gt, n.diameter_host = $diameter_host, n.diameter_realm = $diameter_realm
            WITH n
            MATCH (o:Operator {network_id: $plmn_id})
            MERGE (n)-[:BELONGS_TO_OPERATOR]->(o)
            """,
            {
                **row,
                "ip_address": str(row.get("ip_address") or ""),
                "plmn_id": row.get("plmn_id") or "",
            },
        )
    return len(rows)


def _mirror_diameter() -> int:
    store = get_ontology_store()
    n = 0
    for row in postgres.fetch_all("SELECT * FROM diameter_realm"):
        store.write_merge(
            """
            MERGE (r:DiameterRealm {realm_id: $realm_id})
            SET r.realm = $realm, r.application = $application, r.authorized = $authorized
            WITH r
            MATCH (o:Operator {network_id: $network_id})
            MERGE (o)-[:HAS_DIAMETER_REALM]->(r)
            """,
            dict(row),
        )
        n += 1
    for row in postgres.fetch_all("SELECT * FROM diameter_host"):
        store.write_merge(
            """
            MERGE (h:DiameterHost {diameter_host_id: $diameter_host_id})
            SET h.host_name = $host_name, h.realm = $realm,
                h.ip_address = $ip_address, h.authorized = $authorized
            WITH h
            OPTIONAL MATCH (n:NetworkElement {network_element_id: $network_element_id})
            FOREACH (_ IN CASE WHEN n IS NULL THEN [] ELSE [1] END |
                MERGE (n)-[:HAS_DIAMETER_HOST]->(h)
            )
            """,
            {**row, "ip_address": str(row.get("ip_address") or "")},
        )
        n += 1
    return n


def _mirror_ss7() -> int:
    store = get_ontology_store()
    n = 0
    for row in postgres.fetch_all("SELECT * FROM ss7_global_title"):
        store.write_merge(
            """
            MERGE (g:SS7GlobalTitle {gt_id: $gt_id})
            SET g.global_title = $global_title, g.role = $role, g.authorized = $authorized
            WITH g
            OPTIONAL MATCH (n:NetworkElement {network_element_id: $network_element_id})
            FOREACH (_ IN CASE WHEN n IS NULL THEN [] ELSE [1] END |
                MERGE (n)-[:HAS_GT]->(g)
            )
            """,
            dict(row),
        )
        n += 1
    for row in postgres.fetch_all("SELECT * FROM sccp_address"):
        store.write_merge(
            """
            MERGE (s:SCCPAddress {sccp_id: $sccp_id})
            SET s.point_code = $point_code, s.ssn = $ssn, s.subsystem = $subsystem,
                s.authorized = $authorized
            WITH s
            MATCH (g:SS7GlobalTitle {gt_id: $gt_id})
            MERGE (g)-[:HAS_SCCP_ADDRESS]->(s)
            """,
            dict(row),
        )
        n += 1
    return n


def _mirror_gtp() -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all("SELECT * FROM gtp_gateway")
    for row in rows:
        store.write_merge(
            """
            MERGE (g:GTPGateway {gateway_id: $gateway_id})
            SET g.gateway_name = $gateway_name, g.gateway_role = $gateway_role,
                g.ip_address = $ip_address, g.interface = $interface, g.authorized = $authorized
            WITH g
            MATCH (o:Operator {network_id: $network_id})
            MERGE (o)-[:HAS_GTP_GATEWAY]->(g)
            """,
            {**row, "ip_address": str(row.get("ip_address") or "")},
        )
    return len(rows)


def _mirror_roaming_edges() -> int:
    """PARTNER plmn rows → HAS_ROAMING_RELATIONSHIP from HPLMN."""
    store = get_ontology_store()
    homes = postgres.fetch_all("SELECT network_id FROM plmn WHERE role = 'HPLMN'")
    partners = postgres.fetch_all("SELECT * FROM plmn WHERE role = 'PARTNER'")
    n = 0
    for home in homes:
        for partner in partners:
            store.write_merge(
                """
                MATCH (h:Operator {network_id: $home_id})
                MATCH (p:Operator {network_id: $partner_id})
                MERGE (h)-[rr:HAS_ROAMING_RELATIONSHIP]->(p)
                SET rr.authorized = ($agreement_status = 'ACTIVE'),
                    rr.direction = $direction,
                    rr.mode = 'HOME_ROUTED',
                    rr.status = $agreement_status
                """,
                {
                    "home_id": home["network_id"],
                    "partner_id": partner["network_id"],
                    "agreement_status": partner.get("agreement_status") or "",
                    "direction": partner.get("supported_roaming_direction") or "",
                },
            )
            n += 1
    return n


def _mirror_subscribers() -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all("SELECT * FROM subscriber_state")
    for row in rows:
        store.write_merge(
            """
            MERGE (s:Subscriber {imsi: $imsi})
            SET s.subscriber_id = $subscriber_id,
                s.registration_state = $registration_state,
                s.auth_state = $auth_state,
                s.hplmn_mcc_mnc = $hplmn_mcc_mnc,
                s.current_vplmn_mcc_mnc = $current_vplmn_mcc_mnc
            """,
            dict(row),
        )
    return len(rows)


def _mirror_events(hours: int = 72) -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all(
        """
        SELECT * FROM signaling_event
        WHERE event_time >= now() - interval '72 hours'
           OR event_time IS NULL
        ORDER BY event_time DESC NULLS LAST
        LIMIT 5000
        """,
    )
    for row in rows:
        store.write_merge(
            """
            MERGE (sub:Subscriber {imsi: $imsi})
            MERGE (e:SignalingEvent {event_id: $event_id})
            SET e.event_time = $event_time, e.protocol = $protocol,
                e.message_name = $message_name, e.origin_ne_id = $origin_ne_id,
                e.source_address = $source_address, e.origin_host = $origin_host,
                e.origin_realm = $origin_realm
            MERGE (sub)-[:GENERATES]->(e)
            """,
            {
                **row,
                "imsi": row.get("imsi") or "unknown",
                "event_time": str(row.get("event_time") or ""),
                "origin_ne_id": row.get("origin_ne_id") or "",
                "source_address": row.get("source_address") or "",
                "origin_host": row.get("origin_host") or "",
                "origin_realm": row.get("origin_realm") or "",
            },
        )
    return len(rows)


def _mirror_relationships() -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all("SELECT * FROM signaling_relationship")
    for row in rows:
        store.write_merge(
            """
            MATCH (e1:SignalingEvent {event_id: $event_1_id})
            MATCH (e2:SignalingEvent {event_id: $event_2_id})
            MERGE (e1)-[f:FOLLOWED_BY]->(e2)
            SET f.time_delta_sec = $time_delta_sec, f.expected = $expected,
                f.risk = $risk, f.event_transition = $event_transition
            """,
            {
                **row,
                "time_delta_sec": float(row["time_delta_sec"]) if row.get("time_delta_sec") is not None else None,
            },
        )
    return len(rows)


def _mirror_attack_patterns() -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all("SELECT * FROM attack_pattern")
    for row in rows:
        store.write_merge(
            """
            MERGE (a:AttackPattern {attack_pattern_id: $attack_pattern_id})
            SET a.attack_name = $attack_name, a.protocol_scope = $protocol_scope,
                a.category = $category, a.severity = $severity,
                a.attack_objective = $attack_objective,
                a.sequence_definition = $sequence_definition
            """,
            dict(row),
        )
    return len(rows)


def _mirror_detection_rules() -> int:
    store = get_ontology_store()
    rows = postgres.fetch_all("SELECT * FROM detection_rule")
    for row in rows:
        store.write_merge(
            """
            MERGE (dr:DetectionRule {detection_rule_id: $detection_rule_id})
            SET dr.rule_name = $rule_name, dr.action = $action,
                dr.confidence = $confidence, dr.status = $status,
                dr.suricata_text = $suricata_text, dr.severity = $severity
            WITH dr
            MATCH (ap:AttackPattern {attack_pattern_id: $attack_pattern_id})
            MERGE (ap)-[:DETECTED_BY]->(dr)
            """,
            {
                **row,
                "confidence": float(row["confidence"]) if row.get("confidence") is not None else None,
                "suricata_text": row.get("suricata_text") or "",
            },
        )
    return len(rows)
