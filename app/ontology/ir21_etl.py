"""IR.21 → configuration-layer ETL (new_implementation_plan.md §8 / Phase 1).

Precedence (§11): IR.21 wins for roaming-agreement fields on `plmn` /
`roaming_configuration` / `diameter_realm` / `message_policy`. Live network-
element identity (CMDB-fed `network_element`, `diameter_host`) is only filled
when missing — never overwritten by IR.21.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from app.database import postgres


def feed_from_ir21(*, mirror_graph: bool = False) -> dict[str, Any]:
    """Project enrolled IR.21 documents into the 16-table config layer."""
    if not postgres.is_available():
        return {"ok": False, "error": "postgres unavailable"}
    try:
        from ir21 import postgres as ir21_pg
    except Exception as exc:
        return {"ok": False, "error": f"ir21 unavailable: {exc}"}

    docs = ir21_pg.list_documents()
    counts = {"plmn": 0, "roaming_configuration": 0, "diameter_realm": 0, "network_element": 0, "message_policy": 0}
    for doc in docs:
        did = doc.get("document_id")
        if not did:
            continue
        counts["plmn"] += _upsert_plmn(doc)
        counts["roaming_configuration"] += _upsert_roaming_config(doc)
        counts["diameter_realm"] += _upsert_diameter_realms(did, doc)
        counts["network_element"] += _upsert_network_elements(did, doc)
        counts["message_policy"] += _ensure_default_message_policies(doc)

    result: dict[str, Any] = {"ok": True, "documents": len(docs), "counts": counts}
    if mirror_graph:
        try:
            from app.ontology.mirror import mirror_all

            result["mirror"] = mirror_all()
        except Exception as exc:
            result["mirror"] = {"ok": False, "error": str(exc)}
    return result


def _nid(doc: dict[str, Any]) -> str:
    tadig = (doc.get("tadig") or "").strip().upper()
    if tadig:
        return f"IR21-{tadig}"[:10]
    digest = hashlib.md5(str(doc.get("document_id") or doc.get("file_name") or "x").encode()).hexdigest()[:6]
    return f"IR21{digest}"[:10]


def _upsert_plmn(doc: dict[str, Any]) -> int:
    network_id = _nid(doc)
    mcc = (doc.get("mcc") or "000")[:3]
    mnc = (doc.get("mnc") or "00")[:3]
    plmn_id = f"{mcc}{mnc}"[:6]
    name = (doc.get("organisation_name") or doc.get("presentation_name") or doc.get("file_name") or network_id)[:100]
    tadig = (doc.get("tadig") or "")[:10] or None
    # IR.21 partners are PARTNER + ACTIVE; home network is seeded separately as HPLMN.
    postgres.execute(
        """
        INSERT INTO plmn (
            network_id, operator_name, mcc, mnc, plmn_id, tadig, role,
            supported_roaming_direction, agreement_status, source, updated_at
        ) VALUES (%s,%s,%s,%s,%s,%s,'PARTNER','BIDIRECTIONAL','ACTIVE','IR21', now())
        ON CONFLICT (network_id) DO UPDATE SET
            operator_name = EXCLUDED.operator_name,
            mcc = EXCLUDED.mcc,
            mnc = EXCLUDED.mnc,
            plmn_id = EXCLUDED.plmn_id,
            tadig = COALESCE(EXCLUDED.tadig, plmn.tadig),
            agreement_status = EXCLUDED.agreement_status,
            source = 'IR21',
            updated_at = now()
        WHERE plmn.source IS NULL OR plmn.source IN ('IR21', 'SEED')
        """,
        (network_id, name, mcc, mnc, plmn_id, tadig),
    )
    return 1


def _upsert_roaming_config(doc: dict[str, Any]) -> int:
    network_id = _nid(doc)
    config_id = f"RC{network_id[-6:]}"[:10]
    stack = "Diameter/GTP"
    net = str(doc.get("network_type") or "").lower()
    if "5g" in net:
        tech, gen, stack = "5G", "5G", "SBA/HTTP2/GTP"
    elif "lte" in net or "4g" in net or "epc" in net:
        tech, gen = "LTE", "4G"
    elif "umts" in net or "3g" in net:
        tech, gen, stack = "UMTS", "3G", "SS7/MAP"
    else:
        tech, gen = "LTE", "4G"
    postgres.execute(
        """
        INSERT INTO roaming_configuration
          (config_id, network_id, technology, generation, roaming_mode, signaling_stack, status, updated_at)
        VALUES (%s,%s,%s,%s,'HOME_ROUTED',%s,'ACTIVE', now())
        ON CONFLICT (config_id) DO UPDATE SET
            technology = EXCLUDED.technology,
            generation = EXCLUDED.generation,
            signaling_stack = EXCLUDED.signaling_stack,
            updated_at = now()
        """,
        (config_id, network_id, tech, gen, stack),
    )
    return 1


def _upsert_diameter_realms(document_id: str, doc: dict[str, Any]) -> int:
    network_id = _nid(doc)
    config_id = f"RC{network_id[-6:]}"[:10]
    rows = postgres.fetch_all(
        """
        SELECT DISTINCT realm FROM ir21_diameter_endpoint
        WHERE document_id = %s AND realm IS NOT NULL AND btrim(realm) <> ''
        """,
        (document_id,),
    )
    n = 0
    for i, row in enumerate(rows):
        realm = str(row["realm"]).strip()[:100]
        realm_id = f"DR{_short(network_id, i)}"[:10]
        postgres.execute(
            """
            INSERT INTO diameter_realm (realm_id, network_id, config_id, realm, application, authorized)
            VALUES (%s,%s,%s,%s,'S6a', TRUE)
            ON CONFLICT (realm_id) DO UPDATE SET
                realm = EXCLUDED.realm,
                authorized = TRUE,
                network_id = EXCLUDED.network_id
            """,
            (realm_id, network_id, config_id, realm),
        )
        n += 1
    return n


def _upsert_network_elements(document_id: str, doc: dict[str, Any]) -> int:
    """Fill missing network_element rows only — CMDB wins for existing identity."""
    network_id = _nid(doc)
    rows = postgres.fetch_all(
        """
        SELECT node_type, node_id, gt_address, ip_address
        FROM ir21_network_element WHERE document_id = %s
        """,
        (document_id,),
    )
    n = 0
    for i, row in enumerate(rows):
        ne_id = f"NE{_short(network_id, i)}"[:10]
        existing = postgres.fetch_one(
            "SELECT network_element_id FROM network_element WHERE network_element_id = %s",
            (ne_id,),
        )
        if existing:
            continue
        etype = str(row.get("node_type") or "NODE")[:10]
        name = str(row.get("node_id") or etype)[:50]
        postgres.execute(
            """
            INSERT INTO network_element
              (network_element_id, plmn_id, operator_name, mcc, mnc, tadig,
               element_name, element_type, protocol, gt, ip_address, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'ACTIVE')
            ON CONFLICT (network_element_id) DO NOTHING
            """,
            (
                ne_id,
                network_id,
                (doc.get("organisation_name") or "")[:100],
                (doc.get("mcc") or "")[:3] or None,
                (doc.get("mnc") or "")[:3] or None,
                (doc.get("tadig") or "")[:10] or None,
                name,
                etype,
                _protocol_for(etype),
                (row.get("gt_address") or "")[:20] or None,
                row.get("ip_address") or None,
            ),
        )
        n += 1
    return n


def _ensure_default_message_policies(doc: dict[str, Any]) -> int:
    """IR.21-derived baseline policies (CAT2 inbound auth / location)."""
    network_id = _nid(doc)
    policies = [
        ("MP2", "INBOUND", "SS7/MAP", "CAT2", "SendAuthenticationInfo", "ALERT"),
        ("MP3", "INBOUND", "Diameter", "CAT3.2", "UpdateLocationRequest", "ALERT"),
        ("MP1", "INBOUND", "SS7/MAP", "CAT1", "PROHIBITED", "BLOCK"),
    ]
    n = 0
    for prefix, direction, protocol, category, message, action in policies:
        policy_id = f"{prefix}{network_id[-6:]}"[:10]
        postgres.execute(
            """
            INSERT INTO message_policy
              (policy_id, relationship_id, direction, protocol, category, message_name, action)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (policy_id) DO UPDATE SET
                category = EXCLUDED.category,
                action = EXCLUDED.action
            """,
            (policy_id, network_id, direction, protocol, category, message, action),
        )
        n += 1
    return n


def _short(network_id: str, index: int) -> str:
    base = re.sub(r"[^A-Za-z0-9]", "", network_id)[-5:] or "X"
    return f"{base}{index:02d}"


def _protocol_for(element_type: str) -> str:
    et = (element_type or "").upper()
    if et in ("HLR", "VLR", "MSC", "SMSC", "SGSN"):
        return "SS7/MAP"
    if et in ("HSS", "MME", "DRA", "DEA"):
        return "Diameter"
    if et in ("PGW", "SGW", "GGSN"):
        return "GTP-C"
    return "Diameter/GTP"
