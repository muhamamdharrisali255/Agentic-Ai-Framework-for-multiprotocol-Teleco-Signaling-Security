"""
Category Router — Routes messages through CAT1/CAT2/CAT3 detection engines.

Processing order:
1. CAT1: Immediate rule-based blocking (no context lookup)
2. CAT2: Rule + IR.21 contextual validation
3. CAT3: Stateful subscriber/mobility analysis

First BLOCK or ESCALATE wins. If all pass, ALLOW.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.ids.cat1_engine import CAT1Engine
from app.ids.cat2_engine import CAT2Engine, IR21Store
from app.ids.cat3_engine import CAT3Engine, SubscriberStateStore
from app.ids.decision import Category, Decision, DecisionType


@dataclass
class InspectionResult:
    """Complete inspection result with all category decisions."""
    event_id: str
    timestamp: datetime
    final_decision: Decision
    cat1_result: Decision | None = None
    cat2_result: Decision | None = None
    cat3_result: Decision | None = None
    processing_time_ms: float = 0.0
    enforcement_mode: str = "dry_run"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "final_decision": self.final_decision.to_dict(),
            "cat1_result": self.cat1_result.to_dict() if self.cat1_result else None,
            "cat2_result": self.cat2_result.to_dict() if self.cat2_result else None,
            "cat3_result": self.cat3_result.to_dict() if self.cat3_result else None,
            "processing_time_ms": self.processing_time_ms,
            "enforcement_mode": self.enforcement_mode,
        }


@dataclass
class IDSMetrics:
    """IDS operational metrics."""
    packets_inspected: int = 0
    packets_allowed: int = 0
    packets_blocked: int = 0
    packets_escalated: int = 0
    cat1_matches: int = 0
    cat2_blocks: int = 0
    cat3_escalations: int = 0
    avg_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    active_threats: int = 0
    started_at: datetime = field(default_factory=datetime.utcnow)
    
    def record(self, decision: Decision) -> None:
        """Record a decision in metrics."""
        self.packets_inspected += 1
        self.total_latency_ms += decision.processing_latency_ms
        self.avg_latency_ms = self.total_latency_ms / self.packets_inspected
        
        if decision.decision == DecisionType.ALLOW:
            self.packets_allowed += 1
        elif decision.decision == DecisionType.BLOCK:
            self.packets_blocked += 1
            self.active_threats += 1
            cat = str(decision.category)
            if "CAT1" in cat:
                self.cat1_matches += 1
            elif "CAT2" in cat:
                self.cat2_blocks += 1
        elif decision.decision == DecisionType.ESCALATE:
            self.packets_escalated += 1
            self.active_threats += 1
            self.cat3_escalations += 1
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "packets_inspected": self.packets_inspected,
            "packets_allowed": self.packets_allowed,
            "packets_blocked": self.packets_blocked,
            "packets_escalated": self.packets_escalated,
            "cat1_matches": self.cat1_matches,
            "cat2_blocks": self.cat2_blocks,
            "cat3_escalations": self.cat3_escalations,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "active_threats": self.active_threats,
            "uptime_seconds": (datetime.utcnow() - self.started_at).total_seconds(),
        }


class CategoryRouter:
    """
    Main IDS engine that routes messages through detection categories.
    
    Flow:
    1. CAT1 fast-path: Immediate blocking for prohibited operations
    2. CAT2: Contextual validation with IR.21 lookup
    3. CAT3: Stateful subscriber analysis
    
    Configuration:
    - dry_run: If True, decisions are simulated (no enforcement)
    - skip_cat2: Skip CAT2 for CAT1-blocked messages
    - skip_cat3: Skip CAT3 for blocked messages
    """
    
    def __init__(
        self,
        cat1_engine: CAT1Engine | None = None,
        cat2_engine: CAT2Engine | None = None,
        cat3_engine: CAT3Engine | None = None,
        dry_run: bool = True,
        run_all_categories: bool = False,
    ):
        self.dry_run = dry_run
        self.run_all_categories = run_all_categories
        
        # Initialize engines
        self.cat1 = cat1_engine or CAT1Engine(dry_run=dry_run)
        self.cat2 = cat2_engine or CAT2Engine(dry_run=dry_run)
        self.cat3 = cat3_engine or CAT3Engine(dry_run=dry_run)
        
        # Metrics
        self.metrics = IDSMetrics()
        
        # State
        self.running = False
        self.enforcement_mode = "dry_run" if dry_run else "enforce"
    
    def start(self) -> None:
        """Start the IDS."""
        self.running = True
        self.metrics = IDSMetrics()
    
    def stop(self) -> None:
        """Stop the IDS."""
        self.running = False
    
    def inspect(self, message: dict[str, Any]) -> InspectionResult:
        """
        Inspect a signaling message through all detection categories.
        
        Args:
            message: Parsed signaling message
        
        Returns:
            InspectionResult with all category decisions
        """
        start_time = time.perf_counter()
        event_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        cat1_result: Decision | None = None
        cat2_result: Decision | None = None
        cat3_result: Decision | None = None
        final_decision: Decision | None = None
        
        # Stage 1: CAT1 fast-path
        cat1_result = self.cat1.inspect(message)
        cat1_result.event_id = event_id
        
        if cat1_result.decision == DecisionType.BLOCK:
            final_decision = cat1_result
            if not self.run_all_categories:
                # CAT1 BLOCK - skip other categories
                return self._finalize_result(
                    event_id, timestamp, final_decision,
                    cat1_result, None, None, start_time
                )
        
        # Stage 2: CAT2 contextual validation
        cat2_result = self.cat2.inspect(message)
        cat2_result.event_id = event_id
        
        if cat2_result.decision == DecisionType.BLOCK:
            if final_decision is None:
                final_decision = cat2_result
            if not self.run_all_categories:
                return self._finalize_result(
                    event_id, timestamp, final_decision,
                    cat1_result, cat2_result, None, start_time
                )
        
        # Stage 3: CAT3 stateful analysis
        cat3_result = self.cat3.inspect(message)
        cat3_result.event_id = event_id
        
        if cat3_result.decision in (DecisionType.BLOCK, DecisionType.ESCALATE):
            if final_decision is None:
                final_decision = cat3_result
        
        # If no blocks/escalations, use CAT3 ALLOW (or CAT2 if CAT3 skipped)
        if final_decision is None:
            final_decision = cat3_result or cat2_result or cat1_result
        
        return self._finalize_result(
            event_id, timestamp, final_decision,
            cat1_result, cat2_result, cat3_result, start_time
        )
    
    def _finalize_result(
        self,
        event_id: str,
        timestamp: datetime,
        final_decision: Decision,
        cat1_result: Decision | None,
        cat2_result: Decision | None,
        cat3_result: Decision | None,
        start_time: float,
    ) -> InspectionResult:
        """Finalize and record inspection result."""
        processing_time = (time.perf_counter() - start_time) * 1000
        final_decision.processing_latency_ms = processing_time
        final_decision.dry_run = self.dry_run
        
        # Record metrics
        self.metrics.record(final_decision)
        
        return InspectionResult(
            event_id=event_id,
            timestamp=timestamp,
            final_decision=final_decision,
            cat1_result=cat1_result,
            cat2_result=cat2_result,
            cat3_result=cat3_result,
            processing_time_ms=processing_time,
            enforcement_mode=self.enforcement_mode,
        )
    
    def get_metrics(self) -> dict[str, Any]:
        """Get current IDS metrics."""
        return {
            **self.metrics.to_dict(),
            "running": self.running,
            "enforcement_mode": self.enforcement_mode,
            "dry_run": self.dry_run,
        }
    
    def set_enforcement_mode(self, enforce: bool) -> None:
        """Set enforcement mode."""
        self.dry_run = not enforce
        self.enforcement_mode = "enforce" if enforce else "dry_run"
        self.cat1.dry_run = self.dry_run
        self.cat2.dry_run = self.dry_run
        self.cat3.dry_run = self.dry_run
    
    def add_authorized_gt(self, gt: str) -> None:
        """Add an authorized Global Title."""
        self.cat1.authorized_gt_list.add(gt)
    
    def add_authorized_realm(self, realm: str) -> None:
        """Add an authorized Diameter realm."""
        self.cat1.authorized_realms.add(realm)

    def reload_cdr_partners(self) -> dict[str, Any]:
        """Reload IR.21 / CDR partner context into CAT1–CAT3 engines."""
        stats = self.cat2.ir21_store.reload()
        # Refresh CAT1 authorized GT/realm lists from IR.21
        if getattr(self.cat1, "use_ir21", False):
            self.cat1.authorized_gt_list.clear()
            self.cat1.authorized_realms.clear()
            self.cat1._load_ir21_authorized_sources()
        # Refresh CAT3 PLMN map
        if getattr(self.cat3, "use_ir21", False):
            self.cat3._ir21_partners.clear()
            self.cat3._load_ir21_partners()
        return {
            "ok": True,
            "message": "CDR Sync New complete — IR.21 partners reloaded",
            "partners": stats.get("total_partners", 0),
            "stats": stats,
        }
    
    def get_subscriber_state(self, subscriber_id: str) -> dict[str, Any] | None:
        """Get subscriber state from CAT3 engine."""
        return self.cat3.get_subscriber_state(subscriber_id)
    
    def get_subscriber_timeline(self, subscriber_id: str) -> list[dict[str, Any]]:
        """Get subscriber event timeline from CAT3 engine."""
        return self.cat3.get_subscriber_timeline(subscriber_id)


# Global router instance
_router: CategoryRouter | None = None


def get_router() -> CategoryRouter:
    """Get or create the global CategoryRouter instance."""
    global _router
    if _router is None:
        _router = CategoryRouter(dry_run=True)
    return _router


def reset_router() -> CategoryRouter:
    """Reset and return a new global CategoryRouter instance."""
    global _router
    _router = CategoryRouter(dry_run=True)
    return _router
