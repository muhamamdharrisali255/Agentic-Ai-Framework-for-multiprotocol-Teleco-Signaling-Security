-- Telecom Agentic RAG platform schema (implementation_plan.md §13)

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS operators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    country VARCHAR(8),
    mcc VARCHAR(8),
    mnc VARCHAR(8),
    tadig VARCHAR(16),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roaming_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id UUID REFERENCES operators(id),
    partner_name TEXT NOT NULL,
    tadig VARCHAR(16),
    country VARCHAR(8),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscribers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_code VARCHAR(32) UNIQUE,
    imsi VARCHAR(32) UNIQUE,
    msisdn VARCHAR(32),
    imei VARCHAR(32),
    operator_id UUID REFERENCES operators(id),
    country VARCHAR(8),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    imei VARCHAR(32) UNIQUE,
    subscriber_id UUID REFERENCES subscribers(id),
    device_type TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_code VARCHAR(64) UNIQUE,
    subscriber_id UUID REFERENCES subscribers(id),
    protocol VARCHAR(32),
    source_ip INET,
    destination_ip INET,
    status VARCHAR(32) DEFAULT 'active',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS network_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_code VARCHAR(64) UNIQUE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    protocol VARCHAR(32),
    event_type VARCHAR(64),
    subscriber_id UUID REFERENCES subscribers(id),
    session_id UUID REFERENCES sessions(id),
    severity VARCHAR(16),
    raw_reference TEXT
);

CREATE TABLE IF NOT EXISTS attack_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id VARCHAR(32) UNIQUE NOT NULL,
    name TEXT NOT NULL,
    protocol VARCHAR(32),
    severity VARCHAR(16),
    description TEXT,
    indicators JSONB DEFAULT '[]',
    detection_rules JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(32) UNIQUE NOT NULL,
    name TEXT NOT NULL,
    protocol VARCHAR(32),
    severity VARCHAR(16),
    pattern TEXT,
    attack_pattern_id VARCHAR(32) REFERENCES attack_patterns(attack_id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ids_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_code VARCHAR(64) UNIQUE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    severity VARCHAR(16),
    protocol VARCHAR(32),
    subscriber_id UUID REFERENCES subscribers(id),
    session_id UUID REFERENCES sessions(id),
    attack_pattern_id VARCHAR(32) REFERENCES attack_patterns(attack_id),
    rule_id VARCHAR(32),
    description TEXT
);

CREATE TABLE IF NOT EXISTS domain_dictionary (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    term VARCHAR(64) UNIQUE NOT NULL,
    definition TEXT NOT NULL,
    domain VARCHAR(64),
    aliases JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id VARCHAR(128) UNIQUE NOT NULL,
    title TEXT,
    source VARCHAR(64),
    series VARCHAR(16),
    document_type VARCHAR(64),
    version VARCHAR(32),
    domain VARCHAR(64),
    protocol VARCHAR(32),
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS document_tables (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_id VARCHAR(128) UNIQUE NOT NULL,
    document_id VARCHAR(128) REFERENCES documents(document_id),
    page INT,
    headers JSONB,
    rows JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ingestion_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id VARCHAR(128) UNIQUE NOT NULL,
    file_name TEXT,
    status VARCHAR(32) DEFAULT 'pending',
    chunks_indexed INT DEFAULT 0,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_subscribers_code ON subscribers(subscriber_code);
CREATE INDEX IF NOT EXISTS idx_sessions_subscriber ON sessions(subscriber_id);
CREATE INDEX IF NOT EXISTS idx_alerts_subscriber ON ids_alerts(subscriber_id);
CREATE INDEX IF NOT EXISTS idx_dictionary_term ON domain_dictionary(term);
CREATE INDEX IF NOT EXISTS idx_attack_protocol ON attack_patterns(protocol);
