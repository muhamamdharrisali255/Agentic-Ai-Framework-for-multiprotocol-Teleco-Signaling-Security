"""IDS Decision types and structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class DecisionType(str, Enum):
    """IDS enforcement decision."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class Category(str, Enum):
    """Message category for filtering rules."""
    CAT1 = "CAT1"      # Immediate blocking - prohibited operations
    CAT2 = "CAT2"      # Rule + IR.21 contextual validation
    CAT3_1 = "CAT3.1"  # Sequence/authorization validation
    CAT3_2 = "CAT3.2"  # Impossible travel / mobility analysis


class Protocol(str, Enum):
    """Signaling protocol types."""
    SCCP = "SCCP"
    MAP = "MAP"
    DIAMETER = "Diameter"
    GTP_C = "GTP-C"
    GTP_U = "GTP-U"
    S1AP = "S1AP"
    NGAP = "NGAP"
    UNKNOWN = "UNKNOWN"
    
    @classmethod
    def from_string(cls, value: str) -> "Protocol":
        """Convert string to Protocol enum, case-insensitive."""
        if not value:
            return cls.UNKNOWN
        val_upper = value.upper().replace("-", "_")
        # Try direct match
        for proto in cls:
            if proto.name == val_upper or proto.value.upper() == val_upper:
                return proto
        # Try partial match
        if "DIAMETER" in val_upper or val_upper == "DIA":
            return cls.DIAMETER
        if val_upper in ("SS7",):
            return cls.SCCP
        if val_upper in ("TCAP",):
            return cls.MAP
        if val_upper in ("CAP", "CAMEL"):
            return cls.SCCP
        if "GTP" in val_upper:
            if "U" in val_upper:
                return cls.GTP_U
            return cls.GTP_C
        return cls.UNKNOWN


@dataclass
class RuleMatch:
    """A matched detection rule."""
    rule_id: str
    sid: int
    revision: int = 1
    name: str = ""
    attack_pattern: str = ""
    category: str = ""
    severity: str = "medium"
    rule_text: str = ""
    matched_fields: dict[str, Any] = field(default_factory=dict)
    reference: str = ""


@dataclass
class IR21Evidence:
    """Evidence from IR.21 document lookup."""
    document: str = ""
    section: str = ""
    partner_id: str = ""
    matched_fields: list[str] = field(default_factory=list)
    expected_values: dict[str, Any] = field(default_factory=dict)
    observed_values: dict[str, Any] = field(default_factory=dict)
    mismatches: list[str] = field(default_factory=list)


@dataclass
class SubscriberAnalysis:
    """CAT3 subscriber state analysis result."""
    subscriber_id_masked: str = ""
    distance_km: float = 0.0
    delta_seconds: float = 0.0
    required_velocity_kmh: float = 0.0
    max_plausible_velocity_kmh: float = 1000.0
    sequence_valid: bool = True
    flags: list[str] = field(default_factory=list)
    previous_location: dict[str, Any] = field(default_factory=dict)
    current_location: dict[str, Any] = field(default_factory=dict)
    last_auth_event: dict[str, Any] | None = None


@dataclass  
class ValidationResult:
    """CAT2 validation stages."""
    authorized_procedure: bool = True
    partner_found_in_ir21: bool = True
    parameters_consistent: bool = True
    checks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Decision:
    """Complete IDS decision for a signaling message."""
    
    # Core decision
    decision: DecisionType
    category: Category | str
    confidence: float = 1.0
    
    # Message info
    protocol: Protocol | str = Protocol.UNKNOWN
    procedure: str = ""
    opcode: int | None = None
    source: str = ""
    destination: str = ""
    global_title: str = ""
    origin_realm: str = ""
    origin_host: str = ""
    subscriber_id_masked: str = ""
    
    # Detection details
    attack_pattern: str = ""
    detection_rule: str = ""
    rule_sid: int | None = None
    rule_match: RuleMatch | None = None
    
    # Category-specific evidence
    validation: ValidationResult | None = None  # CAT2
    ir_evidence: IR21Evidence | None = None      # CAT2
    subscriber_analysis: SubscriberAnalysis | None = None  # CAT3
    
    # Enforcement
    enforcement: str = ""  # DROP, ALERT, ESCALATE
    enforcement_confirmed: bool = False
    enforcement_adapter: str = ""
    dry_run: bool = False
    
    # Metadata
    reason: str = ""
    explanation: str = ""
    processing_latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: str = ""
    
    # Processing stages
    stages: list[dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        from app.ids.json_safe import json_safe

        return json_safe({
            "decision": self.decision.value if isinstance(self.decision, DecisionType) else self.decision,
            "category": self.category.value if isinstance(self.category, Category) else self.category,
            "confidence": self.confidence,
            "protocol": self.protocol.value if isinstance(self.protocol, Protocol) else self.protocol,
            "procedure": self.procedure,
            "opcode": self.opcode,
            "source": self.source,
            "destination": self.destination,
            "global_title": self.global_title,
            "origin_realm": self.origin_realm,
            "origin_host": self.origin_host,
            "subscriber_id_masked": self.subscriber_id_masked,
            "attack_pattern": self.attack_pattern,
            "detection_rule": self.detection_rule,
            "rule_sid": self.rule_sid,
            "rule_match": {
                "rule_id": self.rule_match.rule_id,
                "sid": self.rule_match.sid,
                "name": self.rule_match.name,
                "attack_pattern": self.rule_match.attack_pattern,
                "category": self.rule_match.category,
                "matched_fields": self.rule_match.matched_fields,
            } if self.rule_match else None,
            "validation": {
                "authorized_procedure": self.validation.authorized_procedure,
                "partner_found_in_ir21": self.validation.partner_found_in_ir21,
                "parameters_consistent": self.validation.parameters_consistent,
                "checks": self.validation.checks,
            } if self.validation else None,
            "ir_evidence": {
                "document": self.ir_evidence.document,
                "section": self.ir_evidence.section,
                "partner_id": self.ir_evidence.partner_id,
                "matched_fields": self.ir_evidence.matched_fields,
                "expected_values": self.ir_evidence.expected_values,
                "observed_values": self.ir_evidence.observed_values,
                "mismatches": self.ir_evidence.mismatches,
            } if self.ir_evidence else None,
            "subscriber_analysis": {
                "subscriber_id_masked": self.subscriber_analysis.subscriber_id_masked,
                "distance_km": self.subscriber_analysis.distance_km,
                "delta_seconds": self.subscriber_analysis.delta_seconds,
                "required_velocity_kmh": self.subscriber_analysis.required_velocity_kmh,
                "max_plausible_velocity_kmh": self.subscriber_analysis.max_plausible_velocity_kmh,
                "sequence_valid": self.subscriber_analysis.sequence_valid,
                "flags": self.subscriber_analysis.flags,
                "previous_location": self.subscriber_analysis.previous_location,
                "current_location": self.subscriber_analysis.current_location,
            } if self.subscriber_analysis else None,
            "enforcement": self.enforcement,
            "enforcement_confirmed": self.enforcement_confirmed,
            "dry_run": self.dry_run,
            "reason": self.reason,
            "explanation": self.explanation,
            "processing_latency_ms": self.processing_latency_ms,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_id": self.event_id,
            "stages": self.stages,
        })
