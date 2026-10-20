"""Parameterized Cypher templates for the graph specialist (§5.4, §6.3)."""

from __future__ import annotations

import re
from typing import Any

# Each template: name, cypher, required params, optional params.
TEMPLATES: dict[str, dict[str, Any]] = {
    "authorize_identity": {
        "description": "Is this GT/host/realm authorized for an operator?",
        "cypher": """
MATCH (o:Operator)
WHERE ($operator = '' OR toLower(o.operator_name) CONTAINS toLower($operator))
   OR ($network_id <> '' AND o.network_id = $network_id)
   OR ($tadig <> '' AND o.tadig = $tadig)
   OR ($operator = '' AND $network_id = '' AND $tadig = '')
OPTIONAL MATCH (o)<-[:BELONGS_TO_OPERATOR]-(n:NetworkElement)
OPTIONAL MATCH (n)-[:HAS_DIAMETER_HOST]->(h:DiameterHost)
OPTIONAL MATCH (n)-[:HAS_GT]->(g:SS7GlobalTitle)
OPTIONAL MATCH (o)-[:HAS_DIAMETER_REALM]->(r:DiameterRealm)
WITH o, n, h, g, r
WHERE ($host = '' OR (h IS NOT NULL AND toLower(h.host_name) CONTAINS toLower($host)))
  AND ($gt = '' OR (g IS NOT NULL AND g.global_title = $gt))
  AND ($realm = '' OR (r IS NOT NULL AND toLower(r.realm) CONTAINS toLower($realm)))
  AND (
        ($gt <> '' AND g IS NOT NULL)
     OR ($host <> '' AND h IS NOT NULL)
     OR ($realm <> '' AND r IS NOT NULL)
     OR ($gt = '' AND $host = '' AND $realm = '')
  )
RETURN DISTINCT o.network_id AS network_id, o.operator_name AS operator_name,
       o.agreement_status AS agreement_status,
       h.host_name AS host_name, h.authorized AS host_authorized,
       g.global_title AS global_title, g.authorized AS gt_authorized,
       r.realm AS realm, r.authorized AS realm_authorized
LIMIT 20
""",
        "params": ("operator", "network_id", "tadig", "host", "gt", "realm"),
    },
    "ulr_legitimacy": {
        "description": "Is this ULR from the roaming partner legitimate?",
        "cypher": """
MATCH (sub:Subscriber {imsi: $imsi})-[:GENERATES]->(ulr:SignalingEvent)
WHERE ulr.message_name IN ['UpdateLocationRequest','UpdateLocation','ULR']
OPTIONAL MATCH (air:SignalingEvent)-[f:FOLLOWED_BY]->(ulr)
WHERE air.message_name IN ['AuthenticationInformationRequest','AIR','SendAuthenticationInfo','SAI']
OPTIONAL MATCH (n:NetworkElement {network_element_id: ulr.origin_ne_id})-[:BELONGS_TO_OPERATOR]->(o:Operator)
OPTIONAL MATCH (home:Operator {role: 'HPLMN'})-[rr:HAS_ROAMING_RELATIONSHIP]->(o)
RETURN sub.imsi AS imsi, sub.registration_state AS registration_state,
       sub.auth_state AS auth_state,
       o.network_id AS operator_id, o.agreement_status AS agreement_status,
       rr.authorized AS roaming_authorized, rr.direction AS direction, rr.mode AS mode,
       f.time_delta_sec AS time_delta_sec, f.expected AS expected, f.risk AS risk,
       ulr.event_id AS ulr_event_id, ulr.event_time AS ulr_time
LIMIT 10
""",
        "params": ("imsi",),
    },
    "sequence_check": {
        "description": "Inspect FOLLOWED_BY edges for an IMSI window",
        "cypher": """
MATCH (sub:Subscriber {imsi: $imsi})-[:GENERATES]->(e1:SignalingEvent)-[f:FOLLOWED_BY]->(e2:SignalingEvent)
RETURN e1.message_name AS from_msg, e2.message_name AS to_msg,
       f.time_delta_sec AS time_delta_sec, f.expected AS expected, f.risk AS risk,
       e1.event_id AS event_1_id, e2.event_id AS event_2_id
ORDER BY e1.event_time
LIMIT 30
""",
        "params": ("imsi",),
    },
    "attack_detection_rule": {
        "description": "Attack pattern → detection rule edge",
        "cypher": """
MATCH (ap:AttackPattern)-[:DETECTED_BY]->(dr:DetectionRule)
WHERE ($pattern_id = '' OR ap.attack_pattern_id = $pattern_id
       OR toLower(ap.attack_name) CONTAINS toLower($pattern_id))
  AND ($rule_id = '' OR dr.detection_rule_id = $rule_id
       OR toLower(dr.rule_name) CONTAINS toLower($rule_id))
RETURN ap.attack_pattern_id AS attack_pattern_id, ap.attack_name AS attack_name,
       ap.category AS category, ap.severity AS attack_severity,
       dr.detection_rule_id AS detection_rule_id, dr.rule_name AS rule_name,
       dr.action AS action, dr.confidence AS confidence, dr.status AS status,
       dr.suricata_text AS suricata_text
LIMIT 20
""",
        "params": ("pattern_id", "rule_id"),
    },
    "roaming_partner": {
        "description": "Roaming relationship between operators",
        "cypher": """
MATCH (h:Operator {role: 'HPLMN'})-[rr:HAS_ROAMING_RELATIONSHIP]->(p:Operator)
WHERE ($partner = '' OR toLower(p.operator_name) CONTAINS toLower($partner)
       OR p.network_id = $partner OR p.tadig = $partner)
RETURN h.network_id AS hplmn, h.operator_name AS home_name,
       p.network_id AS partner_id, p.operator_name AS partner_name,
       p.agreement_status AS agreement_status,
       rr.authorized AS authorized, rr.direction AS direction, rr.mode AS mode
LIMIT 20
""",
        "params": ("partner",),
    },
}


_IMSI_RE = re.compile(r"\b(\d{14,15})\b")
_GT_RE = re.compile(r"\b(?:GT|global\s*title)\s*[:=]?\s*(\d{6,20})\b", re.I)
_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9.-]+\.(?:example|com|net|epc)[a-z0-9.-]*)\b", re.I)
_REALM_RE = re.compile(r"\brealm\s*[:=]?\s*([a-z0-9.-]+)\b", re.I)
_PATTERN_RE = re.compile(r"\b(AP\d{3}|DR\d{3})\b", re.I)
_TADIG_RE = re.compile(r"\b([A-Z]{5})\b")


def select_template(query: str, agent_ctx: Any = None) -> tuple[str, dict[str, Any]]:
    """Pick a Cypher template and fill parameters from the question / Agent Context."""
    q = query or ""
    low = q.lower()
    params = _extract_params(q, agent_ctx)

    if any(k in low for k in ("suricata", "detection rule", "ap00", "dr00")) or _PATTERN_RE.search(q):
        return "attack_detection_rule", params
    if any(k in low for k in ("ulr", "update location", "legitimate", "air→ulr", "air->ulr")):
        return "ulr_legitimacy", params
    if any(k in low for k in ("sequence", "followed by", "transition", "air", "sai")) and params.get("imsi"):
        return "sequence_check", params
    if any(k in low for k in ("authorized", "authorised", "gt", "host", "realm", "diameter host")):
        return "authorize_identity", params
    if any(k in low for k in ("roaming partner", "roaming agreement", "hplmn", "vplmn")):
        return "roaming_partner", params
    if params.get("imsi"):
        return "ulr_legitimacy", params
    return "roaming_partner", params


def _extract_params(query: str, agent_ctx: Any) -> dict[str, Any]:
    params = {
        "operator": "",
        "network_id": "",
        "tadig": "",
        "host": "",
        "gt": "",
        "realm": "",
        "imsi": "",
        "pattern_id": "",
        "rule_id": "",
        "partner": "",
    }
    m = _IMSI_RE.search(query or "")
    if m:
        params["imsi"] = m.group(1)
    m = _GT_RE.search(query or "")
    if m:
        params["gt"] = m.group(1)
    m = _HOST_RE.search(query or "")
    if m:
        params["host"] = m.group(1)
    m = _REALM_RE.search(query or "")
    if m:
        params["realm"] = m.group(1)
    for m in _PATTERN_RE.finditer(query or ""):
        token = m.group(1).upper()
        if token.startswith("AP"):
            params["pattern_id"] = token
        elif token.startswith("DR"):
            params["rule_id"] = token
    m = _TADIG_RE.search(query or "")
    if m:
        params["tadig"] = m.group(1)
        params["partner"] = m.group(1)

    if agent_ctx is not None:
        sub = getattr(agent_ctx, "subscriber", "") or ""
        if sub.isdigit() and not params["imsi"]:
            params["imsi"] = sub
        extra = getattr(agent_ctx, "extra", {}) or {}
        if isinstance(extra, dict):
            for key in ("imsi", "host", "gt", "realm", "operator"):
                if extra.get(key) and not params.get(key):
                    params[key] = str(extra[key])

    # Operator name heuristic: capitalize words that look like names after "for"/"from"
    m = re.search(r"\b(?:for|from|of)\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?)", query or "")
    if m and not params["operator"]:
        params["operator"] = m.group(1)
        params["partner"] = params["partner"] or m.group(1)
    return params
