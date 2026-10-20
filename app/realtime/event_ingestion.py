"""Event ingestion — Phase 1: JSON store in PostgreSQL network_events."""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from app.database import postgres
from app.realtime.event_schema import NormalizedEvent


def ingest_event(event: NormalizedEvent) -> dict[str, Any]:
    if not postgres.is_available():
        return event.to_dict()
    eid = event.event_id or str(uuid.uuid4())
    postgres.execute(
        """
        INSERT INTO network_events (event_code, timestamp, protocol, event_type, severity, raw_reference)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (event_code) DO NOTHING
        """,
        (
            eid,
            event.timestamp,
            event.protocol,
            event.event_type,
            event.severity,
            json.dumps(event.to_dict()),
        ),
    )
    return event.to_dict()


def list_events(
    *,
    protocol: Optional[str] = None,
    subscriber_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    if not postgres.is_available():
        return []
    sql = "SELECT event_code, timestamp, protocol, event_type, severity, raw_reference FROM network_events WHERE 1=1"
    params: list[Any] = []
    if protocol:
        sql += " AND LOWER(protocol) = LOWER(%s)"
        params.append(protocol)
    sql += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)
    rows = postgres.fetch_all(sql, tuple(params))
    out = []
    for r in rows:
        raw = r.get("raw_reference") or "{}"
        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            payload = {}
        if subscriber_id and payload.get("subscriber_id") != subscriber_id:
            continue
        out.append({
            "event_id": r.get("event_code"),
            "timestamp": str(r.get("timestamp")),
            "protocol": r.get("protocol"),
            "event_type": r.get("event_type"),
            "severity": r.get("severity"),
            **payload,
        })
    return out
