"""
IDS Event Bus — Real-time event distribution for live dashboard updates.

Supports:
- WebSocket connections for live streaming
- Server-Sent Events (SSE) fallback
- Event history for reconnection
- Multiple event types (packets, alerts, decisions, metrics)
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine
import uuid


class EventType(str, Enum):
    """IDS event types."""
    PACKET = "packet"           # New packet captured
    DECISION = "decision"       # IDS decision made
    ALERT = "alert"            # Alert generated
    METRIC = "metric"          # Metrics update
    STATUS = "status"          # System status change
    RULE_UPDATE = "rule_update" # Rule configuration changed
    ERROR = "error"            # System error


@dataclass
class IDSEvent:
    """An IDS event for the event bus."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    data: dict[str, Any]
    category: str = ""
    severity: str = "info"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        from app.ids.json_safe import json_safe

        return json_safe({
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "category": self.category,
            "severity": self.severity,
        })
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    def to_sse(self) -> str:
        """Format as Server-Sent Event."""
        return f"event: {self.event_type.value}\ndata: {self.to_json()}\n\n"


@dataclass
class Alert:
    """IDS Alert for the alert panel."""
    alert_id: str
    timestamp: datetime
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    decision: str  # ALLOW, BLOCK, ESCALATE
    attack_pattern: str = ""
    detection_rule: str = ""
    packet_event_id: str = ""
    subscriber_id_masked: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    analyst_note: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "decision": self.decision,
            "attack_pattern": self.attack_pattern,
            "detection_rule": self.detection_rule,
            "packet_event_id": self.packet_event_id,
            "subscriber_id_masked": self.subscriber_id_masked,
            "evidence": self.evidence,
            "acknowledged": self.acknowledged,
            "analyst_note": self.analyst_note,
        }


class EventBus:
    """
    Event bus for IDS real-time updates.
    
    Features:
    - Async event publishing
    - Multiple subscribers
    - Event history for reconnection
    - Event filtering by type
    """
    
    def __init__(self, history_size: int = 100):
        self._subscribers: list[Callable[[IDSEvent], Coroutine[Any, Any, None]]] = []
        self._sync_subscribers: list[Callable[[IDSEvent], None]] = []
        self._history: deque[IDSEvent] = deque(maxlen=history_size)
        self._alerts: deque[Alert] = deque(maxlen=500)
        self._alert_index: dict[str, Alert] = {}
        self._running = False
        self._event_queue: asyncio.Queue[IDSEvent] | None = None
    
    async def start(self) -> None:
        """Start the event bus."""
        self._running = True
        self._event_queue = asyncio.Queue()
    
    async def stop(self) -> None:
        """Stop the event bus."""
        self._running = False
        if self._event_queue:
            # Signal shutdown
            await self._event_queue.put(None)  # type: ignore
    
    def subscribe(self, callback: Callable[[IDSEvent], Coroutine[Any, Any, None]]) -> None:
        """Subscribe to events (async callback)."""
        self._subscribers.append(callback)
    
    def subscribe_sync(self, callback: Callable[[IDSEvent], None]) -> None:
        """Subscribe to events (sync callback)."""
        self._sync_subscribers.append(callback)
    
    def unsubscribe(self, callback: Callable[[IDSEvent], Coroutine[Any, Any, None]]) -> None:
        """Unsubscribe from events."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)
    
    async def publish(self, event: IDSEvent) -> None:
        """Publish an event to all subscribers."""
        self._history.append(event)
        
        # Notify async subscribers
        for subscriber in self._subscribers:
            try:
                await subscriber(event)
            except Exception as e:
                print(f"[EventBus] Subscriber error: {e}")
        
        # Notify sync subscribers
        for subscriber in self._sync_subscribers:
            try:
                subscriber(event)
            except Exception as e:
                print(f"[EventBus] Sync subscriber error: {e}")
    
    def publish_sync(self, event: IDSEvent) -> None:
        """Publish an event synchronously (for non-async contexts)."""
        self._history.append(event)
        
        # Notify sync subscribers only
        for subscriber in self._sync_subscribers:
            try:
                subscriber(event)
            except Exception as e:
                print(f"[EventBus] Sync subscriber error: {e}")
    
    def create_packet_event(self, packet_data: dict[str, Any]) -> IDSEvent:
        """Create a packet event."""
        return IDSEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.PACKET,
            timestamp=datetime.utcnow(),
            data=packet_data,
            category=packet_data.get("category", ""),
        )
    
    def create_decision_event(self, decision_data: dict[str, Any]) -> IDSEvent:
        """Create a decision event."""
        severity = "info"
        decision = decision_data.get("decision", "")
        if decision == "BLOCK":
            severity = "high"
        elif decision == "ESCALATE":
            severity = "medium"
        
        return IDSEvent(
            event_id=decision_data.get("event_id", str(uuid.uuid4())),
            event_type=EventType.DECISION,
            timestamp=datetime.utcnow(),
            data=decision_data,
            category=decision_data.get("category", ""),
            severity=severity,
        )
    
    def create_alert(self, decision_data: dict[str, Any]) -> Alert:
        """Create an alert from a decision."""
        decision = decision_data.get("decision", "ALLOW")
        category = decision_data.get("category", "")
        
        # Determine severity
        severity = "info"
        if decision == "BLOCK":
            if "CAT1" in category:
                severity = "critical"
            else:
                severity = "high"
        elif decision == "ESCALATE":
            severity = "medium"
        
        # Create title
        title = f"{category} {decision}"
        if decision_data.get("attack_pattern"):
            title = f"{decision_data['attack_pattern']} - {title}"
        
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            category=category,
            severity=severity,
            title=title,
            description=decision_data.get("reason", ""),
            decision=decision,
            attack_pattern=decision_data.get("attack_pattern", ""),
            detection_rule=decision_data.get("detection_rule", ""),
            packet_event_id=decision_data.get("event_id", ""),
            subscriber_id_masked=decision_data.get("subscriber_id_masked", ""),
            evidence={
                "rule_match": decision_data.get("rule_match"),
                "validation": decision_data.get("validation"),
                "ir_evidence": decision_data.get("ir_evidence"),
                "subscriber_analysis": decision_data.get("subscriber_analysis"),
            },
        )
        
        self._alerts.append(alert)
        self._alert_index[alert.alert_id] = alert
        
        return alert
    
    def get_alert(self, alert_id: str) -> Alert | None:
        """Get an alert by ID."""
        return self._alert_index.get(alert_id)
    
    def acknowledge_alert(self, alert_id: str, note: str = "") -> bool:
        """Acknowledge an alert."""
        alert = self._alert_index.get(alert_id)
        if alert:
            alert.acknowledged = True
            alert.analyst_note = note
            return True
        return False
    
    def get_alerts(
        self,
        limit: int = 50,
        severity: str | None = None,
        category: str | None = None,
        acknowledged: bool | None = None,
    ) -> list[Alert]:
        """Get alerts with optional filtering."""
        alerts = list(self._alerts)
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if category:
            alerts = [a for a in alerts if a.category == category]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        
        # Sort by timestamp descending
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        
        return alerts[:limit]
    
    def get_history(
        self,
        limit: int = 50,
        event_type: EventType | None = None,
    ) -> list[IDSEvent]:
        """Get event history with optional filtering."""
        events = list(self._history)
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        # Sort by timestamp descending
        events.sort(key=lambda e: e.timestamp, reverse=True)
        
        return events[:limit]
    
    def create_metric_event(self, metrics: dict[str, Any]) -> IDSEvent:
        """Create a metrics update event."""
        return IDSEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.METRIC,
            timestamp=datetime.utcnow(),
            data=metrics,
        )
    
    def create_status_event(self, status: dict[str, Any]) -> IDSEvent:
        """Create a status change event."""
        return IDSEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.STATUS,
            timestamp=datetime.utcnow(),
            data=status,
        )


# Global event bus instance
_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get or create the global EventBus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus
