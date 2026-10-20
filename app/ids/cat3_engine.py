"""
CAT3 Detection Engine — Stateful Subscriber and Mobility Analysis

CAT3 maintains per-subscriber state for:
- CAT3.1: Sequence validation (auth before mobility)
- CAT3.2: Impossible travel detection (velocity analysis)

Decision: ALLOW, ESCALATE, or BLOCK
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


from app.ids.decision import (
    Category,
    Decision,
    DecisionType,
    IR21Evidence,
    Protocol,
    SubscriberAnalysis,
)


@dataclass
class SubscriberState:
    """Per-subscriber state for CAT3 analysis."""
    subscriber_id: str
    subscriber_id_masked: str = ""
    
    # Location tracking
    last_location_event: dict[str, Any] | None = None
    last_latitude: float | None = None
    last_longitude: float | None = None
    last_cell_id: str = ""
    last_lac: str = ""
    last_mcc_mnc: str = ""
    
    # Timestamp tracking
    last_timestamp: datetime | None = None
    last_location_timestamp: datetime | None = None
    
    # Authentication tracking
    last_auth_event: dict[str, Any] | None = None
    last_auth_timestamp: datetime | None = None
    auth_count: int = 0
    
    # Mobility tracking
    mobility_events: list[dict[str, Any]] = field(default_factory=list)
    location_updates: int = 0
    
    # Risk and flags
    risk_flags: list[str] = field(default_factory=list)
    escalation_count: int = 0
    blocked_count: int = 0
    
    # State metadata
    state_created_at: datetime = field(default_factory=datetime.utcnow)
    state_updated_at: datetime = field(default_factory=datetime.utcnow)
    ttl_seconds: int = 3600  # 1 hour default TTL
    
    def is_expired(self) -> bool:
        """Check if state has expired."""
        if self.state_updated_at is None:
            return True
        age = (datetime.utcnow() - self.state_updated_at).total_seconds()
        return age > self.ttl_seconds
    
    def update_location(
        self,
        latitude: float | None,
        longitude: float | None,
        cell_id: str = "",
        lac: str = "",
        mcc_mnc: str = "",
        timestamp: datetime | None = None,
    ) -> None:
        """Update subscriber location."""
        self.last_location_event = {
            "latitude": latitude,
            "longitude": longitude,
            "cell_id": cell_id,
            "lac": lac,
            "mcc_mnc": mcc_mnc,
            "timestamp": (timestamp or datetime.utcnow()).isoformat(),
        }
        self.last_latitude = latitude
        self.last_longitude = longitude
        self.last_cell_id = cell_id
        self.last_lac = lac
        self.last_mcc_mnc = mcc_mnc
        self.last_location_timestamp = timestamp or datetime.utcnow()
        self.last_timestamp = self.last_location_timestamp
        self.state_updated_at = datetime.utcnow()
        self.location_updates += 1
        
        # Keep last 10 mobility events
        self.mobility_events.append(self.last_location_event)
        if len(self.mobility_events) > 10:
            self.mobility_events = self.mobility_events[-10:]
    
    def update_auth(self, auth_event: dict[str, Any], timestamp: datetime | None = None) -> None:
        """Update authentication state."""
        self.last_auth_event = auth_event
        self.last_auth_timestamp = timestamp or datetime.utcnow()
        self.auth_count += 1
        self.state_updated_at = datetime.utcnow()
    
    def add_flag(self, flag: str) -> None:
        """Add a risk flag."""
        if flag not in self.risk_flags:
            self.risk_flags.append(flag)
        self.state_updated_at = datetime.utcnow()
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "subscriber_id_masked": self.subscriber_id_masked,
            "last_location": self.last_location_event,
            "last_auth": self.last_auth_event,
            "last_timestamp": self.last_timestamp.isoformat() if self.last_timestamp else None,
            "location_updates": self.location_updates,
            "auth_count": self.auth_count,
            "risk_flags": self.risk_flags,
            "escalation_count": self.escalation_count,
            "state_age_seconds": (datetime.utcnow() - self.state_created_at).total_seconds(),
        }


class SubscriberStateStore:
    """In-memory store for subscriber states with TTL expiration."""
    
    def __init__(self, default_ttl: int = 3600):
        self._states: dict[str, SubscriberState] = {}
        self.default_ttl = default_ttl
    
    def get(self, subscriber_id: str) -> SubscriberState | None:
        """Get subscriber state, None if not found or expired."""
        state = self._states.get(subscriber_id)
        if state and state.is_expired():
            del self._states[subscriber_id]
            return None
        return state
    
    def get_or_create(self, subscriber_id: str) -> tuple[SubscriberState, bool]:
        """Get existing state or create new one. Returns (state, is_new)."""
        state = self.get(subscriber_id)
        if state:
            return state, False
        
        state = SubscriberState(
            subscriber_id=subscriber_id,
            subscriber_id_masked=self._mask_imsi(subscriber_id),
            ttl_seconds=self.default_ttl,
        )
        self._states[subscriber_id] = state
        return state, True
    
    def update(self, state: SubscriberState) -> None:
        """Update subscriber state."""
        self._states[state.subscriber_id] = state
    
    def delete(self, subscriber_id: str) -> None:
        """Delete subscriber state."""
        self._states.pop(subscriber_id, None)
    
    def cleanup_expired(self) -> int:
        """Remove expired states. Returns count removed."""
        expired = [sid for sid, s in self._states.items() if s.is_expired()]
        for sid in expired:
            del self._states[sid]
        return len(expired)
    
    def _mask_imsi(self, imsi: str) -> str:
        """Mask IMSI for privacy."""
        if not imsi or len(imsi) < 10:
            return "***"
        return imsi[:5] + "*" * (len(imsi) - 7) + imsi[-2:]


class CAT3Engine:
    """
    CAT3 Stateful Subscriber and Mobility Analysis Engine.
    
    Analyzes with IR.21 context:
    - CAT3.1: Sequence validation (mobility without prior auth)
    - CAT3.2: Impossible travel (velocity > max plausible)
    - CAT3.3: PLMN consistency (subscriber in authorized PLMN)
    
    Decision: ALLOW, ESCALATE, or BLOCK
    """
    
    # Earth radius in kilometers
    EARTH_RADIUS_KM = 6371.0
    
    def __init__(
        self,
        state_store: SubscriberStateStore | None = None,
        max_plausible_velocity_kmh: float = 1000.0,  # ~supersonic
        require_auth_before_mobility: bool = True,
        auth_validity_seconds: int = 1800,  # 30 minutes
        dry_run: bool = False,
        use_ir21: bool = True,
    ):
        self.state_store = state_store or SubscriberStateStore()
        self.max_velocity = max_plausible_velocity_kmh
        self.require_auth = require_auth_before_mobility
        self.auth_validity = auth_validity_seconds
        self.dry_run = dry_run
        self.use_ir21 = use_ir21
        self._ir21_partners: dict[str, dict] = {}
        
        if use_ir21:
            self._load_ir21_partners()
    
    def _load_ir21_partners(self) -> None:
        """Load IR.21 partners for PLMN validation."""
        try:
            from app.ids.rules_3g4g import get_all_ir21_partners
            for partner in get_all_ir21_partners():
                key = f"{partner.mcc}{partner.mnc}"
                self._ir21_partners[key] = {
                    "partner_id": partner.partner_id,
                    "operator_name": partner.operator_name,
                    "country": partner.country,
                    "mcc": partner.mcc,
                    "mnc": partner.mnc,
                    "document_id": partner.document_id or f"IR.21 {partner.tadig_code}",
                    "gt_prefixes": partner.gt_prefixes,
                    "origin_realm": partner.origin_realm,
                    "data_roaming": partner.data_roaming,
                    "lte_roaming": partner.lte_roaming,
                    "voice_roaming": partner.voice_roaming,
                    "agreement_status": partner.agreement_status,
                }
            print(f"[CAT3] Loaded {len(self._ir21_partners)} IR.21 partners for PLMN validation")
        except Exception as e:
            print(f"[CAT3] Failed to load IR.21: {e}")
    
    def _validate_plmn_ir21(self, mcc_mnc: str) -> tuple[bool, dict | None, IR21Evidence | None]:
        """Validate PLMN against IR.21 partners."""
        # Clean and normalize MCC/MNC
        clean = ''.join(c for c in mcc_mnc if c.isdigit())
        if len(clean) >= 5:
            key = clean[:5]  # MCC(3) + MNC(2)
        elif len(clean) >= 3:
            key = clean[:3]  # Try MCC only
        else:
            return True, None, None  # Can't validate
        
        partner = self._ir21_partners.get(key)
        if partner:
            evidence = IR21Evidence(
                document=partner.get("document_id") or "IR.21",
                partner_id=partner["partner_id"],
                matched_fields=["mcc_mnc"],
                expected_values={"authorized_plmn": key, "lte_roaming": partner.get("lte_roaming")},
                observed_values={"visited_plmn": mcc_mnc},
            )
            return True, partner, evidence
        
        # Try with 3-digit MNC
        if len(clean) >= 6:
            key3 = clean[:6]
            partner = self._ir21_partners.get(key3)
            if partner:
                evidence = IR21Evidence(
                    document="IR.21",
                    partner_id=partner["partner_id"],
                    matched_fields=["mcc_mnc"],
                    expected_values={"authorized_plmn": key3},
                    observed_values={"visited_plmn": mcc_mnc},
                )
                return True, partner, evidence
        
        # Unknown PLMN - not in IR.21
        evidence = IR21Evidence(
            document="IR.21",
            partner_id="UNKNOWN",
            matched_fields=[],
            expected_values={"authorized_plmns": list(self._ir21_partners.keys())[:10]},
            observed_values={"visited_plmn": mcc_mnc},
            mismatches=["plmn_not_in_ir21"],
        )
        return False, None, evidence
    
    def inspect(self, event: dict[str, Any]) -> Decision:
        """
        Analyze a subscriber event for CAT3 violations.
        
        Args:
            event: Subscriber event with:
                - imsi or subscriber_id: Subscriber identifier
                - event_type: "auth", "location", "mobility"
                - latitude, longitude: Location coordinates (optional)
                - cell_id, lac, mcc_mnc: Cell location info
                - timestamp: Event timestamp
                - protocol: MAP, Diameter, GTP-C
                - procedure: Specific procedure name
        
        Returns:
            Decision with ALLOW, ESCALATE, or BLOCK
        """
        start_time = time.perf_counter()
        stages: list[dict[str, Any]] = []
        flags: list[str] = []
        
        # Extract subscriber ID
        subscriber_id = str(
            event.get("imsi") or 
            event.get("subscriber_id") or 
            event.get("msisdn") or 
            ""
        )
        if not subscriber_id:
            # No subscriber ID - can't do stateful analysis
            return self._allow_decision(event, "No subscriber ID for stateful analysis", [], start_time)
        
        # Get or create subscriber state
        state, is_new = self.state_store.get_or_create(subscriber_id)
        
        stages.append({
            "stage": "get_subscriber_state",
            "status": "created" if is_new else "existing",
            "subscriber_id_masked": state.subscriber_id_masked,
        })
        
        event_type = str(event.get("event_type", "")).lower()
        procedure = str(event.get("procedure", "")).lower()
        protocol = str(event.get("protocol", ""))
        timestamp = self._parse_timestamp(event.get("timestamp"))
        mcc_mnc = str(event.get("mcc_mnc") or event.get("serving_network") or "")
        if not mcc_mnc and len(subscriber_id) >= 5 and self.use_ir21:
            derived = subscriber_id[:5]
            derived6 = subscriber_id[:6] if len(subscriber_id) >= 6 else ""
            if derived in self._ir21_partners or derived6 in self._ir21_partners:
                mcc_mnc = derived if derived in self._ir21_partners else derived6
        
        # IR.21 PLMN validation
        ir21_evidence = None
        plmn_valid = True
        ir21_partner = None
        
        if self.use_ir21 and mcc_mnc:
            plmn_valid, ir21_partner, ir21_evidence = self._validate_plmn_ir21(mcc_mnc)
            stages.append({
                "stage": "ir21_plmn_validation",
                "status": "valid" if plmn_valid else "unknown_plmn",
                "mcc_mnc": mcc_mnc,
                "ir21_partner": ir21_partner.get("operator_name") if ir21_partner else None,
            })
        
        # Determine if this is an auth or mobility event
        is_auth_event = self._is_auth_event(event_type, procedure)
        is_mobility_event = self._is_mobility_event(event_type, procedure)
        
        if is_auth_event:
            # Update auth state
            state.update_auth(event, timestamp)
            self.state_store.update(state)
            stages.append({
                "stage": "update_auth_state",
                "status": "complete",
                "auth_count": state.auth_count,
            })
            return self._allow_decision(
                event, "Authentication event recorded", stages, start_time,
                subscriber_analysis=self._make_analysis(state),
                ir21_evidence=ir21_evidence,
            )
        
        if is_new and is_mobility_event:
            # First event for this subscriber
            self._update_location_from_event(state, event, timestamp)
            self.state_store.update(state)
            stages.append({
                "stage": "first_observation",
                "status": "recorded",
            })
            return self._allow_decision(
                event, f"First observation for subscriber. IR.21 partner: {ir21_partner.get('operator_name') if ir21_partner else 'N/A'}", 
                stages, start_time,
                subscriber_analysis=self._make_analysis(state),
                ir21_evidence=ir21_evidence,
            )
        
        if is_mobility_event:
            # CAT3.3: PLMN validation against IR.21
            if not plmn_valid and mcc_mnc:
                flags.append("CAT3.3-unknown-plmn")
                state.add_flag("CAT3.3-unknown-plmn")
                stages.append({
                    "stage": "plmn_validation",
                    "status": "fail",
                    "reason": "plmn_not_in_ir21",
                    "mcc_mnc": mcc_mnc,
                })
            elif mcc_mnc:
                stages.append({
                    "stage": "plmn_validation",
                    "status": "pass",
                    "ir21_partner": ir21_partner.get("operator_name") if ir21_partner else None,
                })
            
            # CAT3.1: Sequence validation
            if self.require_auth and not self._has_valid_auth(state, timestamp):
                flags.append("CAT3.1/3.2-sequence-violation")
                state.add_flag("CAT3.1/3.2-sequence-violation")
                stages.append({
                    "stage": "sequence_validation",
                    "status": "fail",
                    "reason": "mobility_without_recent_auth",
                    "last_auth_age_seconds": self._auth_age(state, timestamp),
                })
            else:
                stages.append({
                    "stage": "sequence_validation",
                    "status": "pass",
                })
            
            # CAT3.2: Impossible travel detection
            current_location = self._extract_location(event)
            if current_location and state.last_latitude is not None:
                distance_km = self._haversine_distance(
                    state.last_latitude, state.last_longitude,
                    current_location["latitude"], current_location["longitude"],
                )
                
                delta_seconds = 0.0
                if state.last_location_timestamp and timestamp:
                    delta_seconds = (timestamp - state.last_location_timestamp).total_seconds()
                elif state.last_timestamp and timestamp:
                    delta_seconds = (timestamp - state.last_timestamp).total_seconds()
                
                # Avoid division by zero
                if delta_seconds < 1:
                    delta_seconds = 1
                
                # Calculate required velocity in km/h
                required_velocity = (distance_km / delta_seconds) * 3600
                
                stages.append({
                    "stage": "velocity_analysis",
                    "distance_km": round(distance_km, 2),
                    "delta_seconds": round(delta_seconds, 1),
                    "required_velocity_kmh": round(required_velocity, 1),
                    "max_plausible_velocity_kmh": self.max_velocity,
                })
                
                if required_velocity > self.max_velocity:
                    flags.append("CAT3.2-impossible-travel")
                    state.add_flag("CAT3.2-impossible-travel")
                    state.escalation_count += 1
                    
                    # Create analysis with full details
                    analysis = SubscriberAnalysis(
                        subscriber_id_masked=state.subscriber_id_masked,
                        distance_km=round(distance_km, 2),
                        delta_seconds=round(delta_seconds, 1),
                        required_velocity_kmh=round(required_velocity, 1),
                        max_plausible_velocity_kmh=self.max_velocity,
                        sequence_valid="CAT3.1/3.2-sequence-violation" not in flags,
                        flags=flags,
                        previous_location={
                            "latitude": state.last_latitude,
                            "longitude": state.last_longitude,
                            "cell_id": state.last_cell_id,
                            "mcc_mnc": state.last_mcc_mnc,
                            "timestamp": state.last_location_timestamp.isoformat() if state.last_location_timestamp else None,
                        },
                        current_location=current_location,
                        last_auth_event=state.last_auth_event,
                    )
                    
                    # Update state with new location
                    self._update_location_from_event(state, event, timestamp)
                    self.state_store.update(state)
                    
                    processing_time = (time.perf_counter() - start_time) * 1000
                    
                    return Decision(
                        decision=DecisionType.ESCALATE,
                        category=Category.CAT3_2,
                        confidence=min(1.0, required_velocity / self.max_velocity),
                        protocol=Protocol.from_string(protocol),
                        procedure=procedure,
                        subscriber_id_masked=state.subscriber_id_masked,
                        attack_pattern="AP004",
                        detection_rule="DR004",
                        subscriber_analysis=analysis,
                        ir_evidence=ir21_evidence,
                        enforcement="ESCALATE",
                        enforcement_confirmed=not self.dry_run,
                        dry_run=self.dry_run,
                        reason=f"Impossible travel: {round(distance_km, 1)}km in {round(delta_seconds, 0)}s requires {round(required_velocity, 0)}km/h (max {self.max_velocity}km/h)",
                        explanation=f"CAT3.2 violation: Subscriber location changed faster than physically possible. IR.21 partner: {ir21_partner.get('operator_name') if ir21_partner else 'Unknown'}",
                        processing_latency_ms=processing_time,
                        stages=stages,
                    )
            
            # Update location state
            self._update_location_from_event(state, event, timestamp)
            self.state_store.update(state)
        
        # Check if we have sequence violation or unknown PLMN without impossible travel
        if flags and ("CAT3.1/3.2-sequence-violation" in flags or "CAT3.3-unknown-plmn" in flags):
            state.escalation_count += 1
            self.state_store.update(state)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            
            category = Category.CAT3_1
            reason = "Mobility event without recent authentication"
            explanation = "CAT3.1/3.2 violation: Subscriber mobility without valid auth context"
            
            if "CAT3.3-unknown-plmn" in flags:
                reason = f"Unknown PLMN {mcc_mnc} not in IR.21 roaming agreements"
                explanation = f"CAT3.3 violation: PLMN {mcc_mnc} not found in IR.21 partner database"
            
            return Decision(
                decision=DecisionType.ESCALATE,
                category=category,
                confidence=0.8,
                protocol=Protocol.from_string(protocol),
                procedure=procedure,
                subscriber_id_masked=state.subscriber_id_masked,
                attack_pattern="AP004",
                detection_rule="DR004",
                subscriber_analysis=self._make_analysis(state, flags),
                ir_evidence=ir21_evidence,
                enforcement="ESCALATE",
                enforcement_confirmed=not self.dry_run,
                dry_run=self.dry_run,
                reason=reason,
                explanation=explanation,
                processing_latency_ms=processing_time,
                stages=stages,
            )
        
        return self._allow_decision(
            event, f"All CAT3 checks passed. IR.21 partner: {ir21_partner.get('operator_name') if ir21_partner else 'N/A'}", 
            stages, start_time,
            subscriber_analysis=self._make_analysis(state),
            ir21_evidence=ir21_evidence,
        )
    
    def _is_auth_event(self, event_type: str, procedure: str) -> bool:
        """Check if this is an authentication event."""
        auth_indicators = [
            "auth", "sendauthenticationinfo", "air", "authentication",
            "sai", "sendparameters",
        ]
        combined = f"{event_type} {procedure}".lower()
        return any(ind in combined for ind in auth_indicators)
    
    def _is_mobility_event(self, event_type: str, procedure: str) -> bool:
        """Check if this is a mobility/location event."""
        mobility_indicators = [
            "location", "updatelocation", "ulr", "ula",
            "createsession", "mobility", "handover",
            "ati", "psi", "psl",
        ]
        combined = f"{event_type} {procedure}".lower()
        return any(ind in combined for ind in mobility_indicators)
    
    def _has_valid_auth(self, state: SubscriberState, current_time: datetime | None) -> bool:
        """Check if subscriber has recent valid authentication."""
        if not state.last_auth_timestamp:
            return False
        
        current = current_time or datetime.utcnow()
        age = (current - state.last_auth_timestamp).total_seconds()
        return age <= self.auth_validity
    
    def _auth_age(self, state: SubscriberState, current_time: datetime | None) -> float | None:
        """Get age of last auth in seconds. None when the subscriber has never authenticated."""
        if not state.last_auth_timestamp:
            return None
        current = current_time or datetime.utcnow()
        return (current - state.last_auth_timestamp).total_seconds()
    
    def _extract_location(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Extract location from event."""
        lat = event.get("latitude")
        lon = event.get("longitude")
        
        if lat is not None and lon is not None:
            try:
                return {
                    "latitude": float(lat),
                    "longitude": float(lon),
                    "cell_id": str(event.get("cell_id", "")),
                    "lac": str(event.get("lac", "")),
                    "mcc_mnc": str(event.get("mcc_mnc", "")),
                    "timestamp": event.get("timestamp"),
                }
            except (ValueError, TypeError):
                pass
        
        return None
    
    def _update_location_from_event(
        self, state: SubscriberState, event: dict[str, Any], timestamp: datetime | None
    ) -> None:
        """Update subscriber state with location from event."""
        location = self._extract_location(event)
        if location:
            state.update_location(
                latitude=location["latitude"],
                longitude=location["longitude"],
                cell_id=location.get("cell_id", ""),
                lac=location.get("lac", ""),
                mcc_mnc=location.get("mcc_mnc", ""),
                timestamp=timestamp,
            )
        else:
            # Update timestamp even without coords
            state.last_timestamp = timestamp or datetime.utcnow()
            state.state_updated_at = datetime.utcnow()
    
    def _haversine_distance(
        self, lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate great-circle distance between two points in km."""
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = (
            math.sin(delta_lat / 2) ** 2 +
            math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return self.EARTH_RADIUS_KM * c
    
    def _parse_timestamp(self, ts: Any) -> datetime | None:
        """Parse timestamp from various formats."""
        if ts is None:
            return datetime.utcnow()
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            return datetime.utcfromtimestamp(ts)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.utcnow()
    
    def _make_analysis(
        self, state: SubscriberState, flags: list[str] | None = None
    ) -> SubscriberAnalysis:
        """Create subscriber analysis from state."""
        return SubscriberAnalysis(
            subscriber_id_masked=state.subscriber_id_masked,
            distance_km=0.0,
            delta_seconds=0.0,
            required_velocity_kmh=0.0,
            max_plausible_velocity_kmh=self.max_velocity,
            sequence_valid=not any("sequence" in f for f in (flags or state.risk_flags)),
            flags=flags or state.risk_flags,
            previous_location=state.last_location_event or {},
            current_location={},
            last_auth_event=state.last_auth_event,
        )
    
    def _allow_decision(
        self,
        event: dict[str, Any],
        reason: str,
        stages: list[dict[str, Any]],
        start_time: float,
        subscriber_analysis: SubscriberAnalysis | None = None,
        ir21_evidence: IR21Evidence | None = None,
    ) -> Decision:
        """Create an ALLOW decision."""
        processing_time = (time.perf_counter() - start_time) * 1000
        
        return Decision(
            decision=DecisionType.ALLOW,
            category=Category.CAT3_2,
            confidence=1.0,
            protocol=event.get("protocol", ""),
            procedure=event.get("procedure", ""),
            subscriber_id_masked=subscriber_analysis.subscriber_id_masked if subscriber_analysis else "",
            subscriber_analysis=subscriber_analysis,
            ir_evidence=ir21_evidence,
            enforcement="PASS",
            enforcement_confirmed=True,
            dry_run=self.dry_run,
            reason=reason,
            processing_latency_ms=processing_time,
            stages=stages,
        )
    
    def get_subscriber_state(self, subscriber_id: str) -> dict[str, Any] | None:
        """Get subscriber state for investigation."""
        state = self.state_store.get(subscriber_id)
        return state.to_dict() if state else None
    
    def get_subscriber_timeline(self, subscriber_id: str) -> list[dict[str, Any]]:
        """Get subscriber event timeline."""
        state = self.state_store.get(subscriber_id)
        if not state:
            return []
        return list(state.mobility_events)
