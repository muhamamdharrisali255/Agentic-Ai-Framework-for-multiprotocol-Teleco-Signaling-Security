-- Ontology + taxonomy data model (new_implementation_plan.md §4)
-- Configuration (10) + Runtime (4) + Security intelligence (2)
-- Separate from legacy attack_patterns / detection_rules tables.

-- 4.A Configuration / Knowledge Layer

CREATE TABLE IF NOT EXISTS plmn (
    network_id                  VARCHAR(10) PRIMARY KEY,
    operator_name               VARCHAR(100) NOT NULL,
    mcc                         CHAR(3) NOT NULL,
    mnc                         VARCHAR(3) NOT NULL,
    plmn_id                     VARCHAR(6) NOT NULL,
    tadig                       VARCHAR(10),
    role                        VARCHAR(20) CHECK (role IN ('HPLMN','PARTNER')),
    supported_roaming_direction VARCHAR(20) CHECK (supported_roaming_direction IN ('INBOUND','OUTBOUND','BIDIRECTIONAL')),
    agreement_status            VARCHAR(20) CHECK (agreement_status IN ('OWN_NETWORK','ACTIVE','SUSPENDED','TERMINATED')),
    source                      VARCHAR(20) DEFAULT 'IR21',
    updated_at                  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roaming_configuration (
    config_id        VARCHAR(10) PRIMARY KEY,
    network_id       VARCHAR(10) REFERENCES plmn(network_id),
    technology       VARCHAR(10),
    generation       VARCHAR(5),
    roaming_mode     VARCHAR(20) CHECK (roaming_mode IN ('HOME_ROUTED','LOCAL_BREAKOUT')),
    signaling_stack  VARCHAR(30),
    status           VARCHAR(10) DEFAULT 'ACTIVE',
    updated_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_element (
    network_element_id  VARCHAR(10) PRIMARY KEY,
    plmn_id             VARCHAR(10) REFERENCES plmn(network_id),
    operator_name       VARCHAR(100),
    mcc                 CHAR(3),
    mnc                 VARCHAR(3),
    tadig               VARCHAR(10),
    element_name        VARCHAR(50),
    element_type        VARCHAR(10),
    protocol            VARCHAR(30),
    network_generation  VARCHAR(10),
    gt                  VARCHAR(20),
    sccp_address        VARCHAR(50),
    diameter_host       VARCHAR(150),
    diameter_realm      VARCHAR(100),
    ip_address          INET,
    ip_type             VARCHAR(20),
    role                VARCHAR(10),
    status              VARCHAR(10) DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS diameter_realm (
    realm_id     VARCHAR(10) PRIMARY KEY,
    network_id   VARCHAR(10) REFERENCES plmn(network_id),
    config_id    VARCHAR(10) REFERENCES roaming_configuration(config_id),
    realm        VARCHAR(100) NOT NULL,
    application  VARCHAR(20),
    authorized   BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS diameter_host (
    diameter_host_id   VARCHAR(10) PRIMARY KEY,
    network_element_id VARCHAR(10) REFERENCES network_element(network_element_id),
    network_id         VARCHAR(10) REFERENCES plmn(network_id),
    host_name          VARCHAR(150) NOT NULL,
    realm              VARCHAR(100),
    ip_address         INET,
    authorized         BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS ss7_global_title (
    gt_id              VARCHAR(10) PRIMARY KEY,
    network_id         VARCHAR(10) REFERENCES plmn(network_id),
    config_id          VARCHAR(10) REFERENCES roaming_configuration(config_id),
    global_title       VARCHAR(20) NOT NULL,
    network_element_id VARCHAR(10) REFERENCES network_element(network_element_id),
    role               VARCHAR(20),
    gt_translation_type SMALLINT,
    numbering_plan     VARCHAR(10),
    nature_of_address  VARCHAR(20),
    authorized         BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS sccp_address (
    sccp_id            VARCHAR(10) PRIMARY KEY,
    gt_id              VARCHAR(10) REFERENCES ss7_global_title(gt_id),
    network_id         VARCHAR(10) REFERENCES plmn(network_id),
    point_code         VARCHAR(20),
    ssn                SMALLINT,
    subsystem          VARCHAR(20),
    network_indicator  VARCHAR(20),
    routing_indicator  VARCHAR(5),
    authorized         BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS gtp_gateway (
    gateway_id    VARCHAR(10) PRIMARY KEY,
    network_id    VARCHAR(10) REFERENCES plmn(network_id),
    config_id     VARCHAR(10) REFERENCES roaming_configuration(config_id),
    gateway_name  VARCHAR(100),
    gateway_role  VARCHAR(10),
    ip_address    INET,
    interface     VARCHAR(10),
    authorized    BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS apn_policy (
    apn_policy_id         VARCHAR(10) PRIMARY KEY,
    config_id             VARCHAR(10) REFERENCES roaming_configuration(config_id),
    apn                   VARCHAR(50) NOT NULL,
    technology            VARCHAR(10),
    roaming_mode          VARCHAR(20),
    allowed               BOOLEAN,
    expected_gateway_role VARCHAR(10),
    service_type          VARCHAR(20),
    policy_action         VARCHAR(10) CHECK (policy_action IN ('ALLOW','BLOCK'))
);

CREATE TABLE IF NOT EXISTS message_policy (
    policy_id         VARCHAR(10) PRIMARY KEY,
    relationship_id   VARCHAR(10),
    direction         VARCHAR(10) CHECK (direction IN ('INBOUND','OUTBOUND')),
    protocol          VARCHAR(20),
    category          VARCHAR(10),
    message_name      VARCHAR(50),
    signature_type    VARCHAR(10),
    signature         VARCHAR(100),
    validation_type   VARCHAR(30),
    validation_fields VARCHAR(200),
    action            VARCHAR(10) CHECK (action IN ('ALERT','BLOCK'))
);

-- 4.B Runtime Layer

CREATE TABLE IF NOT EXISTS subscriber_state (
    subscriber_id         VARCHAR(10) PRIMARY KEY,
    imsi                  VARCHAR(20) NOT NULL,
    hplmn_mcc_mnc         VARCHAR(10),
    current_vplmn_mcc_mnc VARCHAR(10),
    location_node_gt      VARCHAR(20),
    registration_state    VARCHAR(20),
    auth_state            VARCHAR(20),
    last_update           TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS session_state (
    session_id         VARCHAR(10) PRIMARY KEY,
    imsi               VARCHAR(20),
    hplmn_mcc          CHAR(3),
    hplmn_mnc          VARCHAR(3),
    vplmn_mcc          CHAR(3),
    vplmn_mnc          VARCHAR(3),
    roaming_direction  VARCHAR(10),
    roaming_mode       VARCHAR(20),
    protocol           VARCHAR(10),
    source_ip          INET,
    source_host        VARCHAR(150),
    source_realm       VARCHAR(100),
    destination_ip     INET,
    destination_host   VARCHAR(150),
    destination_realm  VARCHAR(100),
    apn                VARCHAR(50),
    teid               VARCHAR(20),
    session_status     VARCHAR(10),
    start_time         TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS signaling_event (
    event_id             VARCHAR(20) PRIMARY KEY,
    imsi                 VARCHAR(20),
    event_time           TIMESTAMPTZ DEFAULT now(),
    protocol             VARCHAR(20),
    message_name         VARCHAR(50),
    message_type         VARCHAR(30),
    source_address       VARCHAR(50),
    destination_address  VARCHAR(50),
    origin_realm         VARCHAR(100),
    origin_host          VARCHAR(150),
    origin_ne_id         VARCHAR(10),
    apn                  VARCHAR(50),
    serving_mcc          CHAR(3),
    serving_mnc          VARCHAR(3)
);
CREATE INDEX IF NOT EXISTS idx_signaling_event_imsi_time ON signaling_event (imsi, event_time);

CREATE TABLE IF NOT EXISTS signaling_relationship (
    relationship_id     VARCHAR(10) PRIMARY KEY,
    imsi                VARCHAR(20),
    event_1_id          VARCHAR(20) REFERENCES signaling_event(event_id),
    event_2_id          VARCHAR(20) REFERENCES signaling_event(event_id),
    protocol_transition VARCHAR(30),
    time_delta_sec      NUMERIC(6,2),
    event_transition    VARCHAR(50),
    expected            BOOLEAN,
    risk                VARCHAR(10) CHECK (risk IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

-- 4.C Security Intelligence Layer

CREATE TABLE IF NOT EXISTS attack_pattern (
    attack_pattern_id        VARCHAR(10) PRIMARY KEY,
    attack_name              VARCHAR(150) NOT NULL,
    protocol_scope           VARCHAR(50),
    category                 VARCHAR(20),
    initiating_message       VARCHAR(50),
    sequence_definition      TEXT,
    required_precondition    TEXT,
    suspicious_condition     TEXT,
    correlation_key          VARCHAR(100),
    time_window_sec          INTEGER,
    frequency_threshold      VARCHAR(30),
    roaming_condition        TEXT,
    state_condition          TEXT,
    cross_protocol_condition TEXT,
    attack_objective         VARCHAR(150),
    severity                 VARCHAR(10) CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

CREATE TABLE IF NOT EXISTS detection_rule (
    detection_rule_id  VARCHAR(10) PRIMARY KEY,
    attack_pattern_id  VARCHAR(10) REFERENCES attack_pattern(attack_pattern_id),
    rule_name          VARCHAR(100) NOT NULL,
    protocol           VARCHAR(30),
    category           VARCHAR(20),
    detection_scope    VARCHAR(30),
    required_fields    TEXT,
    rule_logic         TEXT,
    action             VARCHAR(10) CHECK (action IN ('ALERT','BLOCK')),
    severity           VARCHAR(10),
    confidence         NUMERIC(3,2),
    status             VARCHAR(15) DEFAULT 'TESTING',
    rule_version       VARCHAR(10),
    implementation     VARCHAR(50),
    validation_result  VARCHAR(10),
    suricata_text      TEXT
);

CREATE INDEX IF NOT EXISTS idx_plmn_mcc_mnc ON plmn (mcc, mnc);
CREATE INDEX IF NOT EXISTS idx_ne_type ON network_element (element_type);
CREATE INDEX IF NOT EXISTS idx_gt_value ON ss7_global_title (global_title);
CREATE INDEX IF NOT EXISTS idx_diameter_host_name ON diameter_host (host_name);
CREATE INDEX IF NOT EXISTS idx_attack_category ON attack_pattern (category);
CREATE INDEX IF NOT EXISTS idx_detection_status ON detection_rule (status);
