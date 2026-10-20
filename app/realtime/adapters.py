"""Protocol adapters — synthetic JSON normalization (implementation_plan.md §16)."""

from __future__ import annotations

from typing import Any

from app.realtime.event_schema import NormalizedEvent


class SS7Adapter:
    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=str(raw.get("event_id", raw.get("id", ""))),
            protocol="SS7",
            event_type=str(raw.get("event_type", raw.get("operation", "UNKNOWN"))),
            subscriber_id=str(raw.get("subscriber_id", raw.get("imsi", ""))),
            severity=str(raw.get("severity", "MEDIUM")),
            raw_reference=str(raw.get("ref", "")),
        )


class DiameterAdapter:
    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=str(raw.get("event_id", raw.get("id", ""))),
            protocol="Diameter",
            event_type=str(raw.get("command", raw.get("event_type", "UNKNOWN"))),
            subscriber_id=str(raw.get("subscriber_id", "")),
            session_id=str(raw.get("session_id", "")),
            severity=str(raw.get("severity", "MEDIUM")),
            raw_reference=str(raw.get("origin_host", "")),
        )


class GTPAdapter:
    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=str(raw.get("event_id", raw.get("id", ""))),
            protocol="GTP",
            event_type=str(raw.get("event_type", "SESSION_MODIFICATION")),
            subscriber_id=str(raw.get("subscriber_id", "")),
            session_id=str(raw.get("session_id", raw.get("teid", ""))),
            source_ip=str(raw.get("source_ip", "")),
            destination_ip=str(raw.get("destination_ip", "")),
            severity=str(raw.get("severity", "HIGH")),
            raw_reference=str(raw.get("ref", "")),
        )


def get_adapter(protocol: str):
    p = (protocol or "").upper()
    if p == "SS7":
        return SS7Adapter()
    if p == "DIAMETER":
        return DiameterAdapter()
    if p == "GTP":
        return GTPAdapter()
    return GTPAdapter()
