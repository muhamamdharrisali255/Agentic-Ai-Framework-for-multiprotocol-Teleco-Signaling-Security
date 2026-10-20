"""IPS capture agent — observed traffic / IPS alerts → Agent Context.

This is World-1 operational evidence, not a knowledge database. Payloads are
normalized (Suricata EVE, GTP/SS7/Diameter adapters) and stored as events.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.agent.parser import AgentContext, parse_agent_context
from app.realtime.adapters import get_adapter
from app.realtime.event_ingestion import ingest_event
from app.realtime.event_schema import NormalizedEvent


def is_raw_ips_payload(raw: dict[str, Any] | None) -> bool:
    """True for Suricata EVE / adapter traffic, not an already-parsed Agent Context."""
    if not isinstance(raw, dict) or not raw:
        return False
    if isinstance(raw.get("alert"), dict):
        return True
    if raw.get("src_ip") or raw.get("dest_ip") or raw.get("dst_ip"):
        return True
    if raw.get("flow_id") and raw.get("event_type"):
        return True
    return False


def capture(raw: dict[str, Any] | None, *, protocol: str = "") -> dict[str, Any]:
    """Normalize an IPS/IDS/signalling observation, persist it, return Agent Context."""
    payload = dict(raw or {})
    proto = protocol or str(payload.get("protocol") or _guess_protocol(payload) or "")
    event = _normalize(payload, proto)
    try:
        stored = ingest_event(event)
    except Exception:
        stored = event.to_dict()
    signaling = _write_signaling_event(event, payload)
    ctx = context_from_event(event, payload)
    return {
        "event": stored,
        "signaling_event": signaling,
        "agent_context": ctx.as_dict(),
        "protocol": ctx.protocol,
        "entities": ctx.entities,
        "observations": ctx.observations,
    }


def context_from_event(event: NormalizedEvent, raw: dict[str, Any] | None = None) -> AgentContext:
    raw = raw or {}
    alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
    observation = {
        "agent_id": raw.get("agent_id") or raw.get("sensor") or "",
        "agent_ip": raw.get("agent_ip") or "",
        "protocol": event.protocol,
        "subscriber": event.subscriber_id or raw.get("imsi") or "",
        "session": event.session_id,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "severity": event.severity,
        "event_type": event.event_type,
        "entities": _entities(event, raw),
        "observations": _observations(event, raw, alert),
        "ids_alerts": _alerts(raw, alert),
    }
    return parse_agent_context("", observation)


def _normalize(raw: dict[str, Any], protocol: str) -> NormalizedEvent:
    if _is_suricata(raw):
        alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
        proto = (
            protocol
            or str(raw.get("app_proto") or raw.get("proto") or "").upper()
            or "GTP"
        )
        if proto in ("TCP", "UDP", "IP"):
            proto = protocol.upper() if protocol else "GTP"
        return NormalizedEvent(
            event_id=str(raw.get("flow_id") or raw.get("event_id") or uuid.uuid4()),
            protocol=proto,
            event_type=str(raw.get("event_type") or alert.get("category") or "alert"),
            source=str(raw.get("src_ip") or ""),
            destination=str(raw.get("dest_ip") or raw.get("dst_ip") or ""),
            subscriber_id=str(raw.get("subscriber_id") or raw.get("imsi") or ""),
            session_id=str(raw.get("session_id") or raw.get("teid") or ""),
            source_ip=str(raw.get("src_ip") or raw.get("source_ip") or ""),
            destination_ip=str(raw.get("dest_ip") or raw.get("dst_ip") or raw.get("destination_ip") or ""),
            severity=_severity(alert.get("severity") or raw.get("severity")),
            raw_reference=str(alert.get("signature") or raw.get("signature") or ""),
        )
    adapter = get_adapter(protocol or str(raw.get("protocol") or "GTP"))
    event = adapter.normalize(raw)
    if not event.event_id:
        event.event_id = str(uuid.uuid4())
    if not event.source_ip:
        event.source_ip = str(raw.get("src_ip") or raw.get("source_ip") or "")
    if not event.destination_ip:
        event.destination_ip = str(raw.get("dest_ip") or raw.get("dst_ip") or raw.get("destination_ip") or "")
    return event


def _is_suricata(raw: dict[str, Any]) -> bool:
    if isinstance(raw.get("alert"), dict):
        return True
    et = str(raw.get("event_type") or "").lower()
    return et in ("alert", "anomaly", "drop") and ("src_ip" in raw or "dest_ip" in raw)


def _guess_protocol(raw: dict[str, Any]) -> str:
    blob = " ".join(str(v) for v in raw.values() if isinstance(v, (str, int))).lower()
    for proto in ("GTP", "Diameter", "SS7", "MAP", "SIP"):
        if proto.lower() in blob:
            return proto
    app = str(raw.get("app_proto") or "").upper()
    return app if app and app not in ("TCP", "UDP") else ""


def _severity(value: Any) -> str:
    if value is None or value == "":
        return "MEDIUM"
    if isinstance(value, int):
        return {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(value, "MEDIUM")
    return str(value).upper()


def _entities(event: NormalizedEvent, raw: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if event.protocol:
        out.append(event.protocol)
    for key in ("imsi", "imei", "apn", "teid", "mcc", "mnc"):
        if raw.get(key):
            out.append(key.upper())
    return out


def _observations(event: NormalizedEvent, raw: dict[str, Any], alert: dict[str, Any]) -> list[str]:
    out: list[str] = []
    sig = str(alert.get("signature") or raw.get("signature") or event.raw_reference or "").strip()
    if sig:
        out.append(sig)
    cat = str(alert.get("category") or "").strip()
    if cat:
        out.append(cat)
    if event.event_type and event.event_type.lower() not in ("alert", "unknown"):
        out.append(event.event_type)
    extra = raw.get("observations")
    if isinstance(extra, list):
        out.extend(str(x) for x in extra if x)
    elif isinstance(extra, str) and extra.strip():
        out.append(extra.strip())
    return out


def _alerts(raw: dict[str, Any], alert: dict[str, Any]) -> list[str]:
    out: list[str] = []
    sig = str(alert.get("signature") or raw.get("signature") or "").strip()
    if sig:
        out.append(sig)
    sid = alert.get("signature_id") or alert.get("sid") or raw.get("sid")
    if sid:
        out.append(f"sid:{sid}")
    return out


def _write_signaling_event(event: NormalizedEvent, raw: dict[str, Any]) -> dict[str, Any] | None:
    """Also land the observation in ontology runtime table signaling_event (§4.B)."""
    try:
        from app.database import postgres
    except Exception:
        return None
    if not postgres.is_available():
        return None
    alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
    eid = str(raw.get("event_id") or event.event_id or uuid.uuid4())[:20]
    message = str(
        alert.get("signature")
        or raw.get("message_name")
        or event.event_type
        or "alert"
    )[:50]
    row = {
        "event_id": eid,
        "imsi": str(raw.get("imsi") or event.subscriber_id or "")[:20] or None,
        "protocol": (event.protocol or "")[:20],
        "message_name": message,
        "message_type": str(raw.get("message_type") or event.event_type or "")[:30],
        "source_address": (event.source_ip or event.source or "")[:50],
        "destination_address": (event.destination_ip or event.destination or "")[:50],
        "origin_host": str(raw.get("origin_host") or raw.get("host") or "")[:150] or None,
        "origin_realm": str(raw.get("origin_realm") or raw.get("realm") or "")[:100] or None,
        "origin_ne_id": str(raw.get("origin_ne_id") or "")[:10] or None,
        "apn": str(raw.get("apn") or "")[:50] or None,
        "serving_mcc": str(raw.get("serving_mcc") or raw.get("mcc") or "")[:3] or None,
        "serving_mnc": str(raw.get("serving_mnc") or raw.get("mnc") or "")[:3] or None,
    }
    try:
        postgres.execute(
            """
            INSERT INTO signaling_event
              (event_id, imsi, event_time, protocol, message_name, message_type,
               source_address, destination_address, origin_host, origin_realm,
               origin_ne_id, apn, serving_mcc, serving_mnc)
            VALUES (%s,%s,now(),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            (
                row["event_id"], row["imsi"], row["protocol"], row["message_name"], row["message_type"],
                row["source_address"], row["destination_address"], row["origin_host"], row["origin_realm"],
                row["origin_ne_id"], row["apn"], row["serving_mcc"], row["serving_mnc"],
            ),
        )
        rel = _link_signaling_relationship(row)
        if rel:
            row["relationship"] = rel
        return row
    except Exception:
        return None


_EXPECTED_TRANSITIONS = {
    ("AuthenticationInformationRequest", "UpdateLocationRequest"): (True, "LOW"),
    ("AIR", "ULR"): (True, "LOW"),
    ("SendAuthenticationInfo", "UpdateLocation"): (True, "LOW"),
    ("UpdateLocationRequest", "CreateSessionRequest"): (True, "LOW"),
    ("ULR", "CreateSessionRequest"): (True, "LOW"),
}


def _link_signaling_relationship(new_event: dict[str, Any]) -> dict[str, Any] | None:
    """Create FOLLOWED_BY edge from prior event for same IMSI (§4.B / Phase 2)."""
    from app.database import postgres

    imsi = new_event.get("imsi")
    if not imsi:
        return None
    prev = postgres.fetch_one(
        """
        SELECT event_id, protocol, message_name, event_time
        FROM signaling_event
        WHERE imsi = %s AND event_id <> %s
        ORDER BY event_time DESC NULLS LAST
        LIMIT 1
        """,
        (imsi, new_event["event_id"]),
    )
    if not prev:
        return None
    from_msg = str(prev.get("message_name") or "")
    to_msg = str(new_event.get("message_name") or "")
    expected, risk = _EXPECTED_TRANSITIONS.get((from_msg, to_msg), (False, "MEDIUM"))
    # Prefer HIGH when cross-protocol and unexpected.
    if not expected and (prev.get("protocol") or "") != (new_event.get("protocol") or ""):
        risk = "HIGH"
    rel_id = f"R{str(uuid.uuid4()).replace('-', '')[:8]}"[:10]
    transition = f"{prev.get('protocol') or '?'}→{new_event.get('protocol') or '?'}"
    event_transition = f"{from_msg[:24]}→{to_msg[:24]}"[:50]
    try:
        delta = postgres.fetch_one(
            """
            SELECT EXTRACT(EPOCH FROM (now() - %s::timestamptz)) AS sec
            """,
            (prev.get("event_time"),),
        )
        time_delta = float((delta or {}).get("sec") or 0)
    except Exception:
        time_delta = 0.0
    try:
        postgres.execute(
            """
            INSERT INTO signaling_relationship
              (relationship_id, imsi, event_1_id, event_2_id, protocol_transition,
               time_delta_sec, event_transition, expected, risk)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (relationship_id) DO NOTHING
            """,
            (
                rel_id, imsi, prev["event_id"], new_event["event_id"], transition[:30],
                round(time_delta, 2), event_transition, expected, risk,
            ),
        )
    except Exception:
        return None
    return {
        "relationship_id": rel_id,
        "event_1_id": prev["event_id"],
        "event_2_id": new_event["event_id"],
        "expected": expected,
        "risk": risk,
        "event_transition": event_transition,
    }
