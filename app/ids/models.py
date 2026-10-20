"""
IDS Database Models — Persistent storage for events, alerts, rules, and subscriber state.

Tables:
- ids_packet_event: Captured packet events
- ids_alert: Generated alerts
- ids_detection_rule: Detection rules
- ids_subscriber_state: Per-subscriber state for CAT3
- ids_ir21_partner: IR.21 partner records
- ids_audit_log: Audit trail
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


# SQL DDL for IDS tables (PostgreSQL)
IDS_SCHEMA_DDL = """
-- IDS Packet Events
CREATE TABLE IF NOT EXISTS ids_packet_event (
    id SERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    protocol VARCHAR(50),
    source VARCHAR(255),
    destination VARCHAR(255),
    global_title VARCHAR(100),
    origin_realm VARCHAR(255),
    origin_host VARCHAR(255),
    opcode INTEGER,
    procedure VARCHAR(100),
    subscriber_id_masked VARCHAR(50),
    category VARCHAR(20),
    decision VARCHAR(20),
    rule_id VARCHAR(50),
    confidence REAL DEFAULT 1.0,
    processing_latency_ms REAL,
    raw_payload_ref TEXT,
    parsed_fields JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ids_packet_event_timestamp ON ids_packet_event(timestamp);
CREATE INDEX IF NOT EXISTS idx_ids_packet_event_category ON ids_packet_event(category);
CREATE INDEX IF NOT EXISTS idx_ids_packet_event_decision ON ids_packet_event(decision);
CREATE INDEX IF NOT EXISTS idx_ids_packet_event_subscriber ON ids_packet_event(subscriber_id_masked);

-- IDS Alerts
CREATE TABLE IF NOT EXISTS ids_alert (
    id SERIAL PRIMARY KEY,
    alert_id UUID NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    category VARCHAR(20),
    severity VARCHAR(20),
    title VARCHAR(500),
    description TEXT,
    decision VARCHAR(20),
    attack_pattern VARCHAR(50),
    detection_rule VARCHAR(50),
    packet_event_id UUID REFERENCES ids_packet_event(event_id),
    subscriber_id_masked VARCHAR(50),
    evidence JSONB,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by VARCHAR(100),
    analyst_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ids_alert_timestamp ON ids_alert(timestamp);
CREATE INDEX IF NOT EXISTS idx_ids_alert_severity ON ids_alert(severity);
CREATE INDEX IF NOT EXISTS idx_ids_alert_category ON ids_alert(category);
CREATE INDEX IF NOT EXISTS idx_ids_alert_acknowledged ON ids_alert(acknowledged);

-- IDS Detection Rules
CREATE TABLE IF NOT EXISTS ids_detection_rule (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(50) NOT NULL UNIQUE,
    sid INTEGER NOT NULL UNIQUE,
    revision INTEGER DEFAULT 1,
    name VARCHAR(255),
    category VARCHAR(20),
    attack_pattern VARCHAR(50),
    protocol VARCHAR(50),
    severity VARCHAR(20),
    rule_text TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    mode VARCHAR(20) DEFAULT 'enforce',
    opcode INTEGER,
    opcodes INTEGER[],
    authorized_gt_list TEXT[],
    authorized_realms TEXT[],
    action VARCHAR(20) DEFAULT 'BLOCK',
    reference VARCHAR(255),
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ids_detection_rule_category ON ids_detection_rule(category);
CREATE INDEX IF NOT EXISTS idx_ids_detection_rule_enabled ON ids_detection_rule(enabled);
CREATE INDEX IF NOT EXISTS idx_ids_detection_rule_protocol ON ids_detection_rule(protocol);

-- IDS Subscriber State (CAT3)
CREATE TABLE IF NOT EXISTS ids_subscriber_state (
    id SERIAL PRIMARY KEY,
    subscriber_id VARCHAR(50) NOT NULL UNIQUE,
    subscriber_id_masked VARCHAR(50),
    last_location_event JSONB,
    last_latitude REAL,
    last_longitude REAL,
    last_cell_id VARCHAR(50),
    last_lac VARCHAR(50),
    last_mcc_mnc VARCHAR(20),
    last_timestamp TIMESTAMPTZ,
    last_auth_event JSONB,
    last_auth_timestamp TIMESTAMPTZ,
    auth_count INTEGER DEFAULT 0,
    location_updates INTEGER DEFAULT 0,
    mobility_events JSONB DEFAULT '[]',
    risk_flags TEXT[],
    escalation_count INTEGER DEFAULT 0,
    blocked_count INTEGER DEFAULT 0,
    state_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    state_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ttl_seconds INTEGER DEFAULT 3600
);

CREATE INDEX IF NOT EXISTS idx_ids_subscriber_state_updated ON ids_subscriber_state(state_updated_at);
CREATE INDEX IF NOT EXISTS idx_ids_subscriber_state_risk ON ids_subscriber_state(risk_flags);

-- IDS IR.21 Partner Records
CREATE TABLE IF NOT EXISTS ids_ir21_partner (
    id SERIAL PRIMARY KEY,
    partner_id VARCHAR(100) NOT NULL UNIQUE,
    operator_name VARCHAR(255),
    mcc VARCHAR(10),
    mnc VARCHAR(10),
    origin_realm VARCHAR(255),
    origin_host VARCHAR(255),
    source_gateways TEXT[],
    authorized_procedures TEXT[],
    expected_apn TEXT[],
    serving_network_mcc_mnc VARCHAR(20),
    document_id VARCHAR(100),
    document_section VARCHAR(255),
    document_excerpt TEXT,
    agreement_status VARCHAR(20) DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ids_ir21_partner_realm ON ids_ir21_partner(origin_realm);
CREATE INDEX IF NOT EXISTS idx_ids_ir21_partner_mccmnc ON ids_ir21_partner(mcc, mnc);

-- IDS Audit Log
CREATE TABLE IF NOT EXISTS ids_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50),
    action VARCHAR(50),
    actor VARCHAR(100),
    target_type VARCHAR(50),
    target_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ids_audit_log_timestamp ON ids_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_ids_audit_log_event_type ON ids_audit_log(event_type);

-- IDS Metrics Snapshots
CREATE TABLE IF NOT EXISTS ids_metrics_snapshot (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    packets_inspected BIGINT DEFAULT 0,
    packets_allowed BIGINT DEFAULT 0,
    packets_blocked BIGINT DEFAULT 0,
    packets_escalated BIGINT DEFAULT 0,
    cat1_matches BIGINT DEFAULT 0,
    cat2_blocks BIGINT DEFAULT 0,
    cat3_escalations BIGINT DEFAULT 0,
    avg_latency_ms REAL,
    active_threats INTEGER DEFAULT 0,
    enforcement_mode VARCHAR(20),
    interval_seconds INTEGER DEFAULT 60
);

CREATE INDEX IF NOT EXISTS idx_ids_metrics_snapshot_timestamp ON ids_metrics_snapshot(timestamp);
"""


def init_ids_tables():
    """Initialize IDS tables in PostgreSQL."""
    try:
        from app.database import postgres
        if not postgres.is_available():
            print("[IDS] PostgreSQL not available, skipping table init")
            return False
        
        # Execute DDL statements
        for statement in IDS_SCHEMA_DDL.split(';'):
            stmt = statement.strip()
            if stmt and not stmt.startswith('--'):
                try:
                    postgres.execute(stmt + ';')
                except Exception as e:
                    if "already exists" not in str(e).lower():
                        print(f"[IDS] DDL error: {e}")
        
        print("[IDS] Database tables initialized")
        return True
    except Exception as e:
        print(f"[IDS] Table init failed: {e}")
        return False


class IDSRepository:
    """Repository for IDS database operations."""
    
    def __init__(self):
        self._postgres = None
    
    @property
    def postgres(self):
        if self._postgres is None:
            from app.database import postgres
            self._postgres = postgres
        return self._postgres
    
    def save_packet_event(self, event: dict[str, Any]) -> bool:
        """Save a packet event to the database."""
        if not self.postgres.is_available():
            return False
        
        try:
            import json
            self.postgres.execute(
                """
                INSERT INTO ids_packet_event (
                    event_id, timestamp, protocol, source, destination,
                    global_title, origin_realm, origin_host, opcode, procedure,
                    subscriber_id_masked, category, decision, rule_id,
                    confidence, processing_latency_ms, parsed_fields
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    event.get("event_id"),
                    event.get("timestamp", datetime.utcnow()),
                    event.get("protocol"),
                    event.get("source"),
                    event.get("destination"),
                    event.get("global_title"),
                    event.get("origin_realm"),
                    event.get("origin_host"),
                    event.get("opcode"),
                    event.get("procedure"),
                    event.get("subscriber_id_masked"),
                    event.get("category"),
                    event.get("decision"),
                    event.get("rule_id"),
                    event.get("confidence", 1.0),
                    event.get("processing_latency_ms"),
                    json.dumps(event.get("parsed_fields") or {}),
                ),
            )
            return True
        except Exception as e:
            print(f"[IDS] Save packet event failed: {e}")
            return False
    
    def save_alert(self, alert: dict[str, Any]) -> bool:
        """Save an alert to the database."""
        if not self.postgres.is_available():
            return False
        
        try:
            import json
            self.postgres.execute(
                """
                INSERT INTO ids_alert (
                    alert_id, timestamp, category, severity, title, description,
                    decision, attack_pattern, detection_rule, packet_event_id,
                    subscriber_id_masked, evidence
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (alert_id) DO NOTHING
                """,
                (
                    alert.get("alert_id"),
                    alert.get("timestamp", datetime.utcnow()),
                    alert.get("category"),
                    alert.get("severity"),
                    alert.get("title"),
                    alert.get("description"),
                    alert.get("decision"),
                    alert.get("attack_pattern"),
                    alert.get("detection_rule"),
                    alert.get("packet_event_id"),
                    alert.get("subscriber_id_masked"),
                    json.dumps(alert.get("evidence") or {}),
                ),
            )
            return True
        except Exception as e:
            print(f"[IDS] Save alert failed: {e}")
            return False
    
    def get_alerts(
        self,
        limit: int = 50,
        severity: str | None = None,
        category: str | None = None,
        acknowledged: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Get alerts from database."""
        if not self.postgres.is_available():
            return []
        
        try:
            conditions = []
            params = []
            
            if severity:
                conditions.append("severity = %s")
                params.append(severity)
            if category:
                conditions.append("category = %s")
                params.append(category)
            if acknowledged is not None:
                conditions.append("acknowledged = %s")
                params.append(acknowledged)
            
            where = " AND ".join(conditions) if conditions else "1=1"
            params.append(limit)
            
            rows = self.postgres.fetch_all(
                f"""
                SELECT * FROM ids_alert
                WHERE {where}
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                tuple(params),
            )
            return rows
        except Exception as e:
            print(f"[IDS] Get alerts failed: {e}")
            return []
    
    def acknowledge_alert(self, alert_id: str, note: str = "", actor: str = "") -> bool:
        """Acknowledge an alert."""
        if not self.postgres.is_available():
            return False
        
        try:
            self.postgres.execute(
                """
                UPDATE ids_alert
                SET acknowledged = TRUE, acknowledged_at = NOW(),
                    acknowledged_by = %s, analyst_note = %s
                WHERE alert_id = %s
                """,
                (actor, note, alert_id),
            )
            return True
        except Exception as e:
            print(f"[IDS] Acknowledge alert failed: {e}")
            return False
    
    def save_audit_log(
        self,
        event_type: str,
        action: str,
        target_type: str = "",
        target_id: str = "",
        details: dict[str, Any] | None = None,
        actor: str = "",
        ip_address: str | None = None,
    ) -> bool:
        """Save an audit log entry."""
        if not self.postgres.is_available():
            return False
        
        try:
            import json
            self.postgres.execute(
                """
                INSERT INTO ids_audit_log (
                    event_type, action, actor, target_type, target_id, details, ip_address
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event_type,
                    action,
                    actor,
                    target_type,
                    target_id,
                    json.dumps(details or {}),
                    ip_address,
                ),
            )
            return True
        except Exception as e:
            print(f"[IDS] Save audit log failed: {e}")
            return False
    
    def get_metrics_history(self, limit: int = 60) -> list[dict[str, Any]]:
        """Get metrics history from snapshots."""
        if not self.postgres.is_available():
            return []
        
        try:
            return self.postgres.fetch_all(
                """
                SELECT * FROM ids_metrics_snapshot
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                (limit,),
            )
        except Exception as e:
            print(f"[IDS] Get metrics history failed: {e}")
            return []


# Global repository instance
_repository: IDSRepository | None = None


def get_repository() -> IDSRepository:
    """Get or create the global IDSRepository instance."""
    global _repository
    if _repository is None:
        _repository = IDSRepository()
    return _repository
