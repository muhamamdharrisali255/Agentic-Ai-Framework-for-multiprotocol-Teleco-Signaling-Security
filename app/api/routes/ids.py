"""
IDS API Routes — Live signaling firewall inspection endpoints.

Provides:
- /api/ids/status - IDS status and metrics
- /api/ids/start - Start IDS engine
- /api/ids/stop - Stop IDS engine
- /api/ids/inspect - Inspect a message
- /api/ids/traffic - Get recent traffic
- /api/ids/alerts - Get alerts
- /api/ids/rules - Rule management
- /api/ids/metrics - Detailed metrics
- /ws/ids/live - WebSocket for live updates
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.ids.category_router import CategoryRouter, get_router, reset_router
from app.ids.event_bus import EventBus, EventType, IDSEvent, get_event_bus
from app.ids.decision import DecisionType


router = APIRouter()


# ============================================================================
# Pydantic Models
# ============================================================================

class InspectRequest(BaseModel):
    """Request to inspect a signaling message."""
    protocol: str = Field(..., description="Protocol: MAP, Diameter, GTP-C, SCCP")
    procedure: str = Field("", description="Procedure/opcode name")
    opcode: int | None = Field(None, description="MAP opcode or Diameter command code")
    direction: str = Field("INBOUND", description="INBOUND or OUTBOUND")
    source: str = Field("", description="Source address/GT")
    destination: str = Field("", description="Destination address/GT")
    calling_gt: str = Field("", description="Calling Global Title")
    origin_realm: str = Field("", description="Diameter Origin-Realm")
    origin_host: str = Field("", description="Diameter Origin-Host")
    imsi: str = Field("", description="Subscriber IMSI")
    serving_network: str = Field("", description="Serving network MCC/MNC")
    apn: str = Field("", description="Access Point Name")
    source_gateway: str = Field("", description="GTP source gateway")
    map_version: str = Field("", description="MAP version from IR.21 MAP section")
    cap_version: str = Field("", description="CAMEL CAP version from IR.21")
    gtp_version: str = Field("", description="GTP version from IR.21 packet data section")
    latitude: float | None = Field(None, description="Location latitude")
    longitude: float | None = Field(None, description="Location longitude")
    cell_id: str = Field("", description="Cell ID")
    lac: str = Field("", description="Location Area Code")
    mcc_mnc: str = Field("", description="MCC/MNC from location")
    timestamp: str | None = Field(None, description="Event timestamp (ISO format)")
    event_type: str = Field("", description="Event type: auth, location, mobility")
    raw_payload: str = Field("", description="Raw message payload (hex or base64)")


class InspectResponse(BaseModel):
    """Response from message inspection."""
    event_id: str
    decision: str
    category: str
    confidence: float
    enforcement: str
    dry_run: bool
    reason: str
    processing_latency_ms: float
    cat1_result: dict | None = None
    cat2_result: dict | None = None
    cat3_result: dict | None = None


class StatusResponse(BaseModel):
    """IDS status response."""
    running: bool
    enforcement_mode: str
    dry_run: bool
    metrics: dict
    uptime_seconds: float


class AlertResponse(BaseModel):
    """Alert response."""
    alert_id: str
    timestamp: str
    category: str
    severity: str
    title: str
    description: str
    decision: str
    attack_pattern: str
    detection_rule: str
    acknowledged: bool
    analyst_note: str


class AcknowledgeRequest(BaseModel):
    """Request to acknowledge an alert."""
    note: str = Field("", description="Analyst note")


class ReplayRequest(BaseModel):
    """Replay a rules + live-traffic dump through IDS/IPS."""
    path: str = Field(
        "",
        description=(
            "Dump path: JSON dump, Suricata rules .txt, or PCAP/PCAPNG under data/dumps/. "
            "Defaults to data/dumps/signaling_live_dump.json. "
            "Use data/dumps/captures_merged_dump.json for all captures."
        ),
    )


class RuleResponse(BaseModel):
    """Detection rule response."""
    rule_id: str
    sid: int
    name: str
    category: str
    protocol: str
    attack_pattern: str
    action: str
    enabled: bool
    severity: str


# ============================================================================
# IDS Control Endpoints
# ============================================================================

@router.get("/ids/status", response_model=StatusResponse)
async def get_ids_status():
    """Get IDS status and metrics."""
    r = get_router()
    metrics = r.get_metrics()
    return StatusResponse(
        running=r.running,
        enforcement_mode=r.enforcement_mode,
        dry_run=r.dry_run,
        metrics=metrics,
        uptime_seconds=metrics.get("uptime_seconds", 0),
    )


@router.post("/ids/start")
async def start_ids():
    """Start the IDS engine."""
    r = get_router()
    r.start()
    
    # Publish status event
    bus = get_event_bus()
    event = bus.create_status_event({
        "status": "started",
        "enforcement_mode": r.enforcement_mode,
        "timestamp": datetime.utcnow().isoformat(),
    })
    bus.publish_sync(event)
    
    return {"status": "started", "enforcement_mode": r.enforcement_mode}


@router.post("/ids/stop")
async def stop_ids():
    """Stop the IDS engine."""
    r = get_router()
    r.stop()
    
    # Publish status event
    bus = get_event_bus()
    event = bus.create_status_event({
        "status": "stopped",
        "timestamp": datetime.utcnow().isoformat(),
    })
    bus.publish_sync(event)
    
    return {"status": "stopped"}


@router.post("/ids/reset")
async def reset_ids():
    """Reset the IDS engine with fresh state."""
    r = reset_router()
    r.start()
    return {"status": "reset", "enforcement_mode": r.enforcement_mode}


@router.post("/ids/enforcement")
async def set_enforcement_mode(enforce: bool = Query(False)):
    """Set enforcement mode (dry_run or enforce)."""
    r = get_router()
    r.set_enforcement_mode(enforce)
    
    # Publish status event
    bus = get_event_bus()
    event = bus.create_status_event({
        "enforcement_mode": r.enforcement_mode,
        "dry_run": r.dry_run,
        "timestamp": datetime.utcnow().isoformat(),
    })
    bus.publish_sync(event)
    
    return {
        "enforcement_mode": r.enforcement_mode,
        "dry_run": r.dry_run,
    }


# ============================================================================
# Inspection Endpoints
# ============================================================================

@router.post("/ids/inspect", response_model=InspectResponse)
async def inspect_message(req: InspectRequest):
    """
    Inspect a signaling message through CAT1/CAT2/CAT3 engines.
    
    Returns the IDS decision (ALLOW, BLOCK, ESCALATE) with full evidence.
    """
    r = get_router()
    
    # Convert request to message dict
    message = {
        "protocol": req.protocol,
        "procedure": req.procedure,
        "opcode": req.opcode,
        "direction": req.direction,
        "source": req.source,
        "destination": req.destination,
        "calling_gt": req.calling_gt,
        "global_title": req.calling_gt,
        "origin_realm": req.origin_realm,
        "origin_host": req.origin_host,
        "imsi": req.imsi,
        "subscriber_id": req.imsi,
        "serving_network": req.serving_network,
        "apn": req.apn,
        "source_gateway": req.source_gateway,
        "map_version": req.map_version,
        "cap_version": req.cap_version,
        "gtp_version": req.gtp_version,
        "latitude": req.latitude,
        "longitude": req.longitude,
        "cell_id": req.cell_id,
        "lac": req.lac,
        "mcc_mnc": req.mcc_mnc,
        "timestamp": req.timestamp,
        "event_type": req.event_type,
    }
    
    # Run inspection
    result = r.inspect(message)
    final = result.final_decision
    
    # Publish events
    bus = get_event_bus()
    
    # Packet event
    packet_event = bus.create_packet_event({
        "event_id": result.event_id,
        "protocol": req.protocol,
        "procedure": req.procedure,
        "source": req.source or req.calling_gt,
        "destination": req.destination,
        "subscriber_id_masked": final.subscriber_id_masked,
        "timestamp": datetime.utcnow().isoformat(),
    })
    bus.publish_sync(packet_event)
    
    # Decision event
    decision_data = final.to_dict()
    decision_event = bus.create_decision_event(decision_data)
    bus.publish_sync(decision_event)
    
    # Create alert if BLOCK or ESCALATE
    if final.decision in (DecisionType.BLOCK, DecisionType.ESCALATE):
        alert = bus.create_alert(decision_data)
        alert_event = IDSEvent(
            event_id=alert.alert_id,
            event_type=EventType.ALERT,
            timestamp=datetime.utcnow(),
            data=alert.to_dict(),
            category=alert.category,
            severity=alert.severity,
        )
        bus.publish_sync(alert_event)
    
    return InspectResponse(
        event_id=result.event_id,
        decision=final.decision.value if hasattr(final.decision, 'value') else str(final.decision),
        category=final.category.value if hasattr(final.category, 'value') else str(final.category),
        confidence=final.confidence,
        enforcement=final.enforcement,
        dry_run=final.dry_run,
        reason=final.reason,
        processing_latency_ms=result.processing_time_ms,
        cat1_result=result.cat1_result.to_dict() if result.cat1_result else None,
        cat2_result=result.cat2_result.to_dict() if result.cat2_result else None,
        cat3_result=result.cat3_result.to_dict() if result.cat3_result else None,
    )


# ============================================================================
# Traffic and Alerts
# ============================================================================

@router.get("/ids/traffic")
async def get_traffic(
    limit: int = Query(50, ge=1, le=500),
    event_type: str | None = Query(None),
):
    """Get recent live-traffic packet events (default: packet only)."""
    bus = get_event_bus()

    et = EventType.PACKET
    if event_type:
        try:
            et = EventType(event_type)
        except ValueError:
            pass

    events = bus.get_history(limit=limit, event_type=et)
    from app.ids.json_safe import json_safe

    return json_safe({
        "events": [e.to_dict() for e in events],
        "count": len(events),
    })


@router.post("/ids/replay")
async def replay_traffic_dump(path: str = Query("")):
    """Replay a dump of enrolled rules + live traffic through Case 1 IDS/IPS.

    Publishes each event onto the EventBus so Live Traffic / Alerts update.
    """
    from app.ids.dump_replay import DEFAULT_DUMP, load_dump, replay_dump, write_default_dump
    from app.ids.json_safe import json_safe

    dump_path = path or str(DEFAULT_DUMP)
    try:
        dump = load_dump(dump_path)
    except FileNotFoundError:
        write_default_dump()
        dump = load_dump(dump_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Ensure CAT engines are running before replay
    r = get_router()
    if hasattr(r, "start"):
        r.start()

    result = replay_dump(dump, path=dump_path, router=r, publish=True)
    return json_safe(result)


@router.get("/ids/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: str | None = Query(None),
    category: str | None = Query(None),
    acknowledged: bool | None = Query(None),
):
    """Get alerts with optional filtering."""
    bus = get_event_bus()
    alerts = bus.get_alerts(
        limit=limit,
        severity=severity,
        category=category,
        acknowledged=acknowledged,
    )
    return {
        "alerts": [a.to_dict() for a in alerts],
        "count": len(alerts),
    }


@router.get("/ids/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get a specific alert by ID."""
    bus = get_event_bus()
    alert = bus.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.to_dict()


@router.post("/ids/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, req: AcknowledgeRequest):
    """Acknowledge an alert."""
    bus = get_event_bus()
    success = bus.acknowledge_alert(alert_id, req.note)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert = bus.get_alert(alert_id)
    return {"status": "acknowledged", "alert": alert.to_dict() if alert else None}


@router.get("/ids/investigate")
async def investigate_event(
    event_id: str = Query("", description="Packet or decision event id"),
    alert_id: str = Query("", description="Alert id"),
    rule_id: str = Query("", description="Detection rule id"),
):
    """
    Analyst investigation brief: why IDS allowed / blocked / escalated.

    Resolves matching decision history, alert evidence, and enrolled rule text.
    """
    from app.ids.json_safe import json_safe

    bus = get_event_bus()
    target_ids = {x for x in (event_id, alert_id) if x}

    decision_event = None
    packet_event = None
    if target_ids:
        for ev in bus.get_history(limit=500):
            data = ev.data if isinstance(ev.data, dict) else {}
            candidates = {
                ev.event_id,
                str(data.get("event_id") or ""),
                str(data.get("packet_event_id") or ""),
                str(data.get("dump_id") or ""),
            }
            if target_ids.isdisjoint(candidates):
                continue
            if ev.event_type == EventType.DECISION and decision_event is None:
                decision_event = ev
            elif ev.event_type == EventType.PACKET and packet_event is None:
                packet_event = ev
            if decision_event and packet_event:
                break

    alert = None
    if alert_id:
        alert = bus.get_alert(alert_id)
    if alert is None and target_ids:
        for a in bus.get_alerts(limit=200):
            packet_ref = getattr(a, "packet_event_id", "") or ""
            if a.alert_id in target_ids or packet_ref in target_ids:
                alert = a
                break

    decision = decision_event.data if decision_event and isinstance(decision_event.data, dict) else {}
    if not decision and alert is not None:
        evidence = getattr(alert, "evidence", None) or {}
        decision = {
            "decision": alert.decision,
            "category": alert.category,
            "reason": alert.description or "",
            "explanation": "",
            "detection_rule": alert.detection_rule,
            "attack_pattern": alert.attack_pattern,
            "subscriber_id_masked": alert.subscriber_id_masked,
            "rule_match": evidence.get("rule_match"),
            "validation": evidence.get("validation"),
            "ir_evidence": evidence.get("ir_evidence"),
            "subscriber_analysis": evidence.get("subscriber_analysis"),
            "event_id": alert.packet_event_id,
        }

    resolved_rule_id = (
        rule_id
        or (decision.get("detection_rule") if decision else "")
        or (alert.detection_rule if alert else "")
        or ""
    )
    rule = None
    if resolved_rule_id:
        from app.ids.rules_3g4g import (
            get_all_cat1_rules,
            get_all_cat2_rules,
            get_all_cat3_rules,
        )
        for rdef in (*get_all_cat1_rules(), *get_all_cat2_rules(), *get_all_cat3_rules()):
            rid = getattr(rdef, "rule_id", None) or getattr(rdef, "sid", None)
            if str(rid) != str(resolved_rule_id) and str(getattr(rdef, "sid", "")) != str(resolved_rule_id):
                continue
            rule = {
                "rule_id": getattr(rdef, "rule_id", str(resolved_rule_id)),
                "sid": getattr(rdef, "sid", None),
                "name": getattr(rdef, "name", ""),
                "description": getattr(rdef, "description", ""),
                "category": getattr(rdef, "category", ""),
                "protocol": getattr(rdef, "protocol", ""),
                "attack_pattern": getattr(rdef, "attack_pattern", ""),
                "action": getattr(rdef, "action", ""),
                "validation_logic": getattr(rdef, "validation_logic", ""),
                "ir21_checks": getattr(rdef, "ir21_checks", None),
                "reference": getattr(rdef, "gsma_reference", None) or getattr(rdef, "reference", ""),
                "rule_text": getattr(rdef, "rule_text", ""),
                "severity": getattr(rdef, "severity", ""),
            }
            break

    reason = (decision or {}).get("reason") or (alert.description if alert else "") or ""
    explanation = (decision or {}).get("explanation") or ""
    if not explanation and rule:
        bits = [
            f"Matched rule {rule.get('rule_id')}: {rule.get('name') or 'unnamed'}.",
            rule.get("description") or "",
        ]
        if rule.get("validation_logic"):
            bits.append(f"Validation: {rule['validation_logic']}")
        explanation = " ".join(b for b in bits if b).strip()
    if not explanation and reason:
        explanation = reason
    if not explanation:
        decision_label = (decision or {}).get("decision") or (alert.decision if alert else "UNKNOWN")
        category_label = (decision or {}).get("category") or (alert.category if alert else "")
        explanation = (
            f"IDS returned {decision_label}"
            + (f" under {category_label}" if category_label else "")
            + ". Detailed engine rationale was not retained for this event."
        )

    packet = packet_event.to_dict() if packet_event else None
    return json_safe({
        "event_id": event_id or (decision or {}).get("event_id") or (alert.packet_event_id if alert else ""),
        "decision": (decision or {}).get("decision") or (alert.decision if alert else ""),
        "category": (decision or {}).get("category") or (alert.category if alert else ""),
        "reason": reason,
        "explanation": explanation,
        "confidence": (decision or {}).get("confidence"),
        "enforcement": (decision or {}).get("enforcement"),
        "dry_run": (decision or {}).get("dry_run"),
        "attack_pattern": (decision or {}).get("attack_pattern") or (alert.attack_pattern if alert else ""),
        "detection_rule": resolved_rule_id,
        "rule": rule,
        "rule_match": (decision or {}).get("rule_match"),
        "validation": (decision or {}).get("validation"),
        "ir_evidence": (decision or {}).get("ir_evidence"),
        "subscriber_analysis": (decision or {}).get("subscriber_analysis"),
        "stages": (decision or {}).get("stages"),
        "alert": alert.to_dict() if alert else None,
        "packet": packet,
    })


# ============================================================================
# Metrics
# ============================================================================

@router.get("/ids/metrics")
async def get_metrics():
    """Get detailed IDS metrics."""
    r = get_router()
    return r.get_metrics()


# ============================================================================
# Subscriber State
# ============================================================================

@router.get("/ids/subscribers/{subscriber_id}/state")
async def get_subscriber_state(subscriber_id: str):
    """Get subscriber state for investigation."""
    r = get_router()
    state = r.get_subscriber_state(subscriber_id)
    if not state:
        raise HTTPException(status_code=404, detail="Subscriber state not found")
    return state


@router.get("/ids/subscribers/{subscriber_id}/timeline")
async def get_subscriber_timeline(subscriber_id: str):
    """Get subscriber event timeline."""
    r = get_router()
    timeline = r.get_subscriber_timeline(subscriber_id)
    return {"timeline": timeline, "count": len(timeline)}


# ============================================================================
# Rules Management
# ============================================================================

@router.get("/ids/rules")
async def get_rules(
    category: str | None = Query(None),
    protocol: str | None = Query(None),
    generation: str | None = Query(None),
    enabled: bool | None = Query(None),
):
    """Get all detection rules (CAT1, CAT2, CAT3)."""
    from app.ids.rules_3g4g import (
        get_all_cat1_rules, 
        get_all_cat2_rules, 
        get_all_cat3_rules,
    )
    
    rules = []
    
    # CAT1 Rules
    if not category or category.upper() == "CAT1":
        for rule in get_all_cat1_rules():
            if protocol and rule.protocol.upper() != protocol.upper():
                continue
            if generation and generation.upper() not in rule.generation.upper():
                continue
            if enabled is not None and rule.enabled != enabled:
                continue
            
            rules.append({
                "rule_id": rule.rule_id,
                "sid": rule.sid,
                "name": rule.name,
                "description": rule.description,
                "category": "CAT1",
                "protocol": rule.protocol,
                "generation": rule.generation,
                "attack_pattern": rule.attack_pattern,
                "action": rule.action,
                "enabled": rule.enabled,
                "severity": rule.severity,
                "opcode": rule.opcode or rule.command_code or rule.message_type,
                "reference": rule.gsma_reference,
                "rule_text": rule.rule_text,
            })
    
    # CAT2 Rules
    if not category or category.upper() == "CAT2":
        for rule in get_all_cat2_rules():
            if protocol and rule.protocol.upper() != protocol.upper():
                continue
            if generation and generation.upper() not in rule.generation.upper():
                continue
            if enabled is not None and rule.enabled != enabled:
                continue
            
            rules.append({
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "category": "CAT2",
                "protocol": rule.protocol,
                "generation": rule.generation,
                "procedure": rule.procedure,
                "direction": rule.direction,
                "ir21_checks": rule.ir21_checks,
                "validation_logic": rule.validation_logic,
                "enabled": rule.enabled,
                "severity": rule.severity,
                "reference": rule.gsma_reference,
            })
    
    # CAT3 Rules
    if not category or category.upper().startswith("CAT3"):
        for rule in get_all_cat3_rules():
            if protocol and rule.protocol.upper() != protocol.upper():
                continue
            if generation and generation.upper() not in rule.generation.upper():
                continue
            if enabled is not None and rule.enabled != enabled:
                continue
            
            rules.append({
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "category": rule.category,
                "protocol": rule.protocol,
                "generation": rule.generation,
                "analysis_type": rule.analysis_type,
                "parameters": rule.parameters,
                "ai_model": rule.ai_model,
                "threshold": rule.threshold,
                "enabled": rule.enabled,
                "severity": rule.severity,
                "reference": rule.gsma_reference,
                "ir21_checks": ["partner_plmn", "lte_roaming", "agreement_status"],
            })
    
    return {"rules": rules, "count": len(rules)}


@router.get("/ids/partners")
async def get_partners():
    """Get all IR.21 roaming partners with SS7, Diameter, and GTP context."""
    from app.ids.rules_3g4g import get_all_ir21_partners, partner_to_context, ir21_rule_coverage
    
    partners = [partner_to_context(p) for p in get_all_ir21_partners()]
    coverage = ir21_rule_coverage()
    return {"partners": partners, "count": len(partners), "coverage": coverage}


@router.post("/ids/cdr/sync-new")
async def sync_cdr_new():
    """
    CDR Sync New — reload IR.21 / partner CDR context into the live IDS engines.
    Pulls predefined + database partners and refreshes CAT1–CAT3 caches.
    """
    r = get_router()
    result = r.reload_cdr_partners()
    bus = get_event_bus()
    bus.publish_sync(
        bus.create_status_event(
            {
                "action": "cdr_sync_new",
                "partners": result.get("partners", 0),
                "message": result.get("message", ""),
            }
        )
    )
    return result


@router.get("/ids/ir21/context")
async def get_ir21_context():
    """IR.21 contextual coverage: rules per category and protocol (SS7/Diameter/GTP)."""
    from app.ids.rules_3g4g import (
        get_all_cat1_rules,
        get_all_cat2_rules,
        get_all_cat3_rules,
        get_all_ir21_partners,
        ir21_rule_coverage,
        partner_to_context,
    )
    cat2 = get_all_cat2_rules()
    return {
        "coverage": ir21_rule_coverage(),
        "rules": {
            "CAT1": [
                {"rule_id": r.rule_id, "protocol": r.protocol, "generation": r.generation, "contextual": "IR.21 GT/realm/IMSI authorization"}
                for r in get_all_cat1_rules()
            ],
            "CAT2": [
                {
                    "rule_id": r.rule_id,
                    "protocol": r.protocol,
                    "generation": r.generation,
                    "procedure": r.procedure,
                    "ir21_checks": r.ir21_checks,
                    "validation_logic": r.validation_logic,
                    "reference": r.gsma_reference,
                    "contextual": bool(r.ir21_checks),
                }
                for r in cat2
            ],
            "CAT3": [
                {
                    "rule_id": r.rule_id,
                    "protocol": r.protocol,
                    "generation": r.generation,
                    "analysis_type": r.analysis_type,
                    "ir21_checks": ["partner_plmn", "lte_roaming", "agreement_status"],
                    "contextual": True,
                }
                for r in get_all_cat3_rules()
            ],
        },
        "partners": [partner_to_context(p) for p in get_all_ir21_partners()],
    }


@router.get("/ids/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get a specific rule by ID."""
    r = get_router()
    
    for rule in r.cat1.rules:
        if rule.rule_id == rule_id:
            return {
                "rule_id": rule.rule_id,
                "sid": rule.sid,
                "name": rule.name,
                "category": "CAT1",
                "protocol": rule.protocol,
                "attack_pattern": rule.attack_pattern,
                "detection_rule": rule.detection_rule,
                "action": rule.action,
                "enabled": rule.enabled,
                "severity": rule.severity,
                "opcode": rule.opcode,
                "opcodes": rule.opcodes,
                "reference": rule.reference,
                "rule_text": rule.rule_text,
            }
    
    raise HTTPException(status_code=404, detail="Rule not found")


# ============================================================================
# WebSocket Live Updates
# ============================================================================

class ConnectionManager:
    """Manage WebSocket connections for live updates."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


@router.websocket("/ids/live")
async def websocket_live(websocket: WebSocket):
    """WebSocket endpoint for live IDS updates."""
    await manager.connect(websocket)
    
    # Subscribe to event bus
    bus = get_event_bus()
    
    async def on_event(event: IDSEvent):
        try:
            await websocket.send_text(event.to_json())
        except Exception:
            pass
    
    bus.subscribe(on_event)
    
    try:
        # Send initial status
        r = get_router()
        status_event = bus.create_status_event({
            "connected": True,
            "running": r.running,
            "enforcement_mode": r.enforcement_mode,
            "metrics": r.get_metrics(),
        })
        await websocket.send_text(status_event.to_json())
        
        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                # Handle ping/pong
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_text(json.dumps({
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat(),
                }))
    
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(on_event)
        manager.disconnect(websocket)


# ============================================================================
# Server-Sent Events (SSE) Fallback
# ============================================================================

@router.get("/ids/stream")
async def stream_events():
    """SSE endpoint for live IDS updates (WebSocket fallback)."""
    
    async def event_generator():
        bus = get_event_bus()
        queue: asyncio.Queue[IDSEvent] = asyncio.Queue()
        
        def on_event(event: IDSEvent):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass
        
        bus.subscribe_sync(on_event)
        
        try:
            # Send initial status
            r = get_router()
            status = bus.create_status_event({
                "connected": True,
                "running": r.running,
                "enforcement_mode": r.enforcement_mode,
            })
            yield status.to_sse()
            
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield event.to_sse()
                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield f"event: heartbeat\ndata: {json.dumps({'timestamp': datetime.utcnow().isoformat()})}\n\n"
        
        except asyncio.CancelledError:
            pass
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================================
# Demo / Test Endpoints
# ============================================================================

@router.post("/ids/demo/cat1")
async def demo_cat1():
    """Demo CAT1 blocking with unauthorized ATI."""
    return await inspect_message(InspectRequest(
        protocol="MAP",
        procedure="AnyTimeInterrogation",
        opcode=71,
        direction="INBOUND",
        calling_gt="882990012345678",  # External GT
        source="10.0.0.1",
        destination="10.0.0.2",
        imsi="419050123456789",
    ))


@router.post("/ids/demo/cat2")
async def demo_cat2():
    """Demo CAT2 IR.21 contextual validation — unknown Diameter realm is blocked."""
    return await inspect_message(InspectRequest(
        protocol="Diameter",
        procedure="Update-Location-Request",
        opcode=316,
        direction="INBOUND",
        origin_realm="unknown.operator.com",
        origin_host="mme.unknown.operator.com",
        source="10.0.0.1",
        destination="10.0.0.2",
        imsi="419050123456789",
        serving_network="999-99",
    ))


@router.post("/ids/demo/cat2-ss7")
async def demo_cat2_ss7():
    """Demo CAT2 SS7/MAP IR.21 GT contextual match (Maxis / Zain)."""
    return await inspect_message(InspectRequest(
        protocol="MAP",
        procedure="UpdateLocation",
        opcode=2,
        direction="INBOUND",
        calling_gt="965961234567",
        imsi="419021234567890",
        map_version="MAPv3",
    ))


@router.post("/ids/demo/cat3")
async def demo_cat3_impossible_travel():
    """Demo CAT3 impossible travel — known IR.21 partner, auth, then Kuwait→London."""
    auth = await inspect_message(InspectRequest(
        protocol="Diameter",
        procedure="Authentication-Information-Request",
        opcode=318,
        direction="INBOUND",
        origin_realm="zain.com.kw",
        origin_host="mme1.zain.com.kw",
        imsi="419021234567890",
        event_type="auth",
        timestamp="2026-09-18T12:00:00",
    ))
    result1 = await inspect_message(InspectRequest(
        protocol="Diameter",
        procedure="Update-Location-Request",
        opcode=316,
        direction="INBOUND",
        origin_realm="zain.com.kw",
        origin_host="mme1.zain.com.kw",
        imsi="419021234567890",
        latitude=29.3759,  # Kuwait City
        longitude=47.9774,
        event_type="location",
        timestamp="2026-09-18T12:01:00",
    ))
    result2 = await inspect_message(InspectRequest(
        protocol="Diameter",
        procedure="Update-Location-Request",
        opcode=316,
        direction="INBOUND",
        origin_realm="zain.com.kw",
        origin_host="mme1.zain.com.kw",
        imsi="419021234567890",
        latitude=51.5074,  # London
        longitude=-0.1278,
        event_type="location",
        timestamp="2026-09-18T12:04:00",
    ))
    return {
        "auth_event": auth,
        "first_event": result1,
        "second_event": result2,
        "explanation": "Second ULR should ESCALATE CAT3.2 impossible travel (Kuwait→London in 3 minutes).",
    }
