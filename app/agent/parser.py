"""Agent Parser — observed network data → structured Agent Context.

Raw packets and logs are never sent to the LLM. This module turns an optional
observation payload (and identifiers already present in the question) into a
compact context the orchestrator can plan over.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_IMSI_RE = re.compile(r"\bIMSI\s*[:=]?\s*(\d{10,15})\b", re.I)
_AGENT_ID_RE = re.compile(r"\bAgent(?:\s+ID)?\s*[:=]?\s*([A-Za-z0-9_-]{2,})\b", re.I)
_SESSION_RE = re.compile(
    r"\b(?:session|sess)(?:\s*id)?\s*[:=]\s*([A-Za-z0-9_-]{3,})\b",
    re.I,
)
_SESSION_STOP = {
    "hijack", "hijacking", "management", "context", "modification",
    "establishment", "teardown", "setup", "info", "information",
}


@dataclass
class AgentContext:
    """World-1 snapshot: what is happening in the network, already structured."""

    agent_id: str = ""
    agent_ip: str = ""
    protocol: str = ""
    subscriber: str = ""
    session: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    entities: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    severity: str = ""
    event_type: str = ""
    ids_alerts: list[str] = field(default_factory=list)
    ids_rule: dict[str, Any] = field(default_factory=dict)
    ids_action: str = ""
    blocked: bool = False
    ips_traffic: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def has_observation(self) -> bool:
        return bool(
            self.observations
            or self.agent_id
            or self.session
            or self.source_ip
            or self.ids_alerts
            or self.event_type
        )

    def entity_map(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.protocol:
            out["protocol"] = self.protocol
        if self.subscriber:
            if self.subscriber.upper().startswith("SUB"):
                out["subscriber_id"] = self.subscriber
            elif self.subscriber.isdigit():
                out["imsi"] = self.subscriber
            else:
                out["subscriber_id"] = self.subscriber
        if self.session:
            out["session_id"] = self.session
        return out

    def as_markdown(self) -> str:
        if not self.has_observation and not self.protocol:
            return ""
        lines = ["[Agent Context — observed network evidence]"]
        pairs = [
            ("Agent ID", self.agent_id),
            ("Agent IP", self.agent_ip),
            ("Protocol", self.protocol),
            ("Subscriber", self.subscriber),
            ("Session", self.session),
            ("Source IP", self.source_ip),
            ("Destination IP", self.destination_ip),
            ("Event type", self.event_type),
            ("Severity", self.severity),
        ]
        for label, value in pairs:
            if value:
                lines.append(f"- {label}: {value}")
        if self.entities:
            lines.append("- Entities: " + ", ".join(self.entities))
        if self.observations:
            lines.append("- Observations:")
            for obs in self.observations:
                lines.append(f"  - {obs}")
        if self.ids_alerts:
            lines.append("- IDS/IPS: " + "; ".join(self.ids_alerts))
        if self.ids_rule:
            rid = self.ids_rule.get("detection_rule_id") or self.ids_rule.get("policy_id") or "rule"
            act = self.ids_action or self.ids_rule.get("action") or ""
            status = self.ids_rule.get("status") or ""
            lines.append(
                f"- IDS rule ({status}): {rid} action={act}"
                + (" **BLOCKED**" if self.blocked else "")
            )
            if self.ids_rule.get("summary"):
                lines.append(f"  - {self.ids_rule['summary'][:240]}")
        if self.ips_traffic:
            lines.append("- IPS traffic:")
            for key in ("protocol", "event_type", "source_ip", "subscriber", "event_id"):
                val = self.ips_traffic.get(key)
                if val:
                    lines.append(f"  - {key}: {val}")
        lines.append("[/Agent Context]")
        return "\n".join(lines)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_ip": self.agent_ip,
            "protocol": self.protocol,
            "subscriber": self.subscriber,
            "session": self.session,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "entities": self.entities,
            "observations": self.observations,
            "severity": self.severity,
            "event_type": self.event_type,
            "ids_alerts": self.ids_alerts,
            "ids_rule": self.ids_rule,
            "ids_action": self.ids_action,
            "blocked": self.blocked,
            "ips_traffic": self.ips_traffic,
        }


def parse_agent_context(
    query: str,
    observation: dict[str, Any] | None = None,
) -> AgentContext:
    """Build Agent Context from an explicit observation payload and/or the question."""
    ctx = AgentContext()
    if observation:
        _apply_payload(ctx, observation)
    _apply_query(ctx, query or "")
    ctx.entities = list(dict.fromkeys(ctx.entities))
    ctx.observations = list(dict.fromkeys(ctx.observations))
    return ctx


def _apply_payload(ctx: AgentContext, raw: dict[str, Any]) -> None:
    ctx.agent_id = str(raw.get("agent_id") or raw.get("agentId") or ctx.agent_id)
    ctx.agent_ip = str(raw.get("agent_ip") or raw.get("agentIp") or ctx.agent_ip)
    ctx.protocol = str(raw.get("protocol") or ctx.protocol)
    ctx.subscriber = str(
        raw.get("subscriber") or raw.get("subscriber_id") or raw.get("imsi") or ctx.subscriber
    )
    ctx.session = str(raw.get("session") or raw.get("session_id") or ctx.session)
    ctx.source_ip = str(raw.get("source_ip") or raw.get("src") or ctx.source_ip)
    ctx.destination_ip = str(raw.get("destination_ip") or raw.get("dst") or ctx.destination_ip)
    ctx.severity = str(raw.get("severity") or ctx.severity)
    ctx.event_type = str(raw.get("event_type") or raw.get("eventType") or ctx.event_type)
    ents = raw.get("entities") or []
    if isinstance(ents, list):
        ctx.entities.extend(str(e) for e in ents if e)
    obs = raw.get("observations") or raw.get("observation")
    if isinstance(obs, str) and obs.strip():
        ctx.observations.append(obs.strip())
    elif isinstance(obs, list):
        ctx.observations.extend(str(o) for o in obs if o)
    alerts = raw.get("ids_alerts") or raw.get("alerts") or []
    if isinstance(alerts, list):
        ctx.ids_alerts.extend(str(a) for a in alerts if a)
    elif isinstance(alerts, str) and alerts.strip():
        ctx.ids_alerts.append(alerts.strip())
    ids_rule = raw.get("ids_rule")
    if isinstance(ids_rule, dict):
        ctx.ids_rule = ids_rule
    ctx.ids_action = str(raw.get("ids_action") or ctx.ids_action or "")
    if raw.get("blocked") is not None:
        ctx.blocked = bool(raw.get("blocked"))
    ips_traffic = raw.get("ips_traffic")
    if isinstance(ips_traffic, dict):
        ctx.ips_traffic = ips_traffic
    skip = {
        "agent_id", "agentId", "agent_ip", "agentIp", "protocol", "subscriber",
        "subscriber_id", "imsi", "session", "session_id", "source_ip", "src",
        "destination_ip", "dst", "severity", "event_type", "eventType",
        "entities", "observations", "observation", "ids_alerts", "alerts",
        "ids_rule", "ids_action", "blocked", "ips_traffic", "detection_rules",
        "ips_event_id", "rule_status",
    }
    ctx.extra = {k: v for k, v in raw.items() if k not in skip}


def _apply_query(ctx: AgentContext, query: str) -> None:
    blob = _extract_json_blob(query)
    if blob:
        _apply_payload(ctx, blob)

    if not ctx.agent_id:
        m = _AGENT_ID_RE.search(query)
        if m:
            ctx.agent_id = m.group(1)
    if not ctx.subscriber:
        m = _IMSI_RE.search(query)
        if m:
            ctx.subscriber = m.group(1)
    if not ctx.session:
        m = _SESSION_RE.search(query)
        if m and m.group(1).lower() not in _SESSION_STOP:
            ctx.session = m.group(1)

    ips = _IP_RE.findall(query)
    if ips and not ctx.source_ip:
        ctx.source_ip = ips[0]
    if len(ips) > 1 and not ctx.destination_ip:
        ctx.destination_ip = ips[1]

    if not ctx.protocol:
        for proto in ("GTP", "Diameter", "SS7", "MAP", "SIP"):
            if re.search(rf"\b{re.escape(proto)}\b", query, re.I):
                ctx.protocol = proto
                ctx.entities.append(proto)
                break

    low = query.lower()
    network_grounded = bool(
        ctx.agent_id or ctx.session or ctx.source_ip or ctx.subscriber or ctx.ids_alerts
    )
    if network_grounded:
        for marker, text in (
            ("abnormal", "abnormal signalling behaviour"),
            ("unusual", "unusual signalling"),
            ("suspicious", "suspicious activity"),
            ("anomal", "observed anomaly"),
            ("hijack", "possible session hijack indicators"),
            ("flood", "request flooding / abnormal frequency"),
        ):
            if marker in low:
                ctx.observations.append(text)

    for name in ("IMSI", "IMEI", "MCC", "MNC", "APN", "TEID", "GT"):
        if re.search(rf"\b{name}\b", query, re.I):
            ctx.entities.append(name)


def _extract_json_blob(query: str) -> dict[str, Any] | None:
    start = (query or "").find("{")
    end = (query or "").rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(query[start : end + 1])
        return data if isinstance(data, dict) else None
    except Exception:
        return None
