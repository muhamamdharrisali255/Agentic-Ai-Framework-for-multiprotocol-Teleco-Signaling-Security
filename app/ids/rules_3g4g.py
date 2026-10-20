"""
Predefined Detection Rules for 3G/4G Signaling Security

Based on GSMA FS.11, FS.19, IR.21 specifications:
- CAT1: Immediate blocking (prohibited operations)
- CAT2: Contextual validation (IR.21 partner checks)  
- CAT3: AI-driven behavioral/stateful rules

Protocols:
- 3G: SS7/SCCP, MAP, CAP, TCAP
- 4G: Diameter (S6a, S6d, S13, SWx), GTP-C v2
"""

from dataclasses import dataclass, field
from typing import Any

# ============================================================================
# CAT1 Rules — Immediate Blocking (3G/4G)
# ============================================================================

@dataclass
class CAT1Rule:
    """Category 1 rule for immediate blocking."""
    rule_id: str
    sid: int
    name: str
    description: str
    protocol: str  # MAP, Diameter, GTP-C, SCCP
    generation: str  # 3G, 4G, 3G/4G
    opcode: int | None = None
    opcodes: list[int] = field(default_factory=list)
    command_code: int | None = None  # Diameter
    message_type: int | None = None  # GTP-C
    attack_pattern: str = ""
    gsma_reference: str = ""
    action: str = "BLOCK"
    severity: str = "critical"
    rule_text: str = ""
    enabled: bool = True


# 3G SS7/MAP CAT1 Rules (GSMA FS.11)
CAT1_MAP_RULES = [
    CAT1Rule(
        rule_id="CAT1-MAP-001",
        sid=1000001,
        name="Unauthorized SendIMSI",
        description="SendIMSI from external network - subscriber identity theft attempt",
        protocol="MAP",
        generation="3G",
        opcode=58,  # sendIMSI
        attack_pattern="AP001",
        gsma_reference="FS.11 Section 5.2",
        severity="critical",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-SendIMSI-External"; map.opcode:58; sid:1000001;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-002",
        sid=1000002,
        name="Unauthorized AnyTimeInterrogation",
        description="ATI from external GT - location tracking attempt",
        protocol="MAP",
        generation="3G",
        opcode=71,  # anyTimeInterrogation
        attack_pattern="AP004",
        gsma_reference="FS.11 Section 5.3",
        severity="critical",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-ATI-External"; map.opcode:71; sid:1000002;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-003",
        sid=1000003,
        name="Unauthorized ProvideSubscriberInfo",
        description="PSI from external network - subscriber data harvesting",
        protocol="MAP",
        generation="3G",
        opcode=70,  # provideSubscriberInfo
        attack_pattern="AP003",
        gsma_reference="FS.11 Section 5.4",
        severity="critical",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-PSI-External"; map.opcode:70; sid:1000003;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-004",
        sid=1000004,
        name="Unauthorized SendRoutingInfoForSM to HLR",
        description="SRI-SM to HLR from external - SMS interception setup",
        protocol="MAP",
        generation="3G",
        opcode=45,  # sendRoutingInfoForSM
        attack_pattern="AP004",
        gsma_reference="FS.11 Section 5.5",
        severity="high",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-SRISM-HLR"; map.opcode:45; sid:1000004;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-005",
        sid=1000005,
        name="Unauthorized InsertSubscriberData",
        description="ISD from external - subscriber profile manipulation",
        protocol="MAP",
        generation="3G",
        opcode=7,  # insertSubscriberData
        attack_pattern="AP005",
        gsma_reference="FS.11 Section 5.6",
        severity="critical",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-ISD-External"; map.opcode:7; sid:1000005;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-006",
        sid=1000006,
        name="Unauthorized DeleteSubscriberData",
        description="DSD from external - subscriber profile deletion",
        protocol="MAP",
        generation="3G",
        opcode=8,  # deleteSubscriberData
        attack_pattern="AP006",
        gsma_reference="FS.11 Section 5.6",
        severity="critical",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-DSD-External"; map.opcode:8; sid:1000006;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-007",
        sid=1000007,
        name="Unauthorized SendParameters (Deprecated)",
        description="Deprecated SendParameters operation - legacy attack",
        protocol="MAP",
        generation="3G",
        opcode=9,  # sendParameters
        attack_pattern="AP007",
        gsma_reference="FS.11 Section 5.7",
        severity="high",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-SendParams"; map.opcode:9; sid:1000007;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-008",
        sid=1000008,
        name="Unauthorized ProvideSubscriberLocation",
        description="PSL from external - precise location tracking",
        protocol="MAP",
        generation="3G",
        opcode=83,  # provideSubscriberLocation
        attack_pattern="AP008",
        gsma_reference="FS.11 Section 5.8",
        severity="critical",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-PSL-External"; map.opcode:83; sid:1000008;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-009",
        sid=1000009,
        name="Unauthorized RegisterSS",
        description="RegisterSS from external - call forwarding hijack",
        protocol="MAP",
        generation="3G",
        opcode=10,  # registerSS
        attack_pattern="AP009",
        gsma_reference="FS.11 Section 5.9",
        severity="high",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-RegisterSS"; map.opcode:10; sid:1000009;)',
    ),
    CAT1Rule(
        rule_id="CAT1-MAP-010",
        sid=1000010,
        name="Unauthorized CancelLocation",
        description="Cancel Location from unauthorized source - DoS attack",
        protocol="MAP",
        generation="3G",
        opcode=3,  # cancelLocation
        attack_pattern="AP010",
        gsma_reference="FS.11 Section 5.10",
        severity="critical",
        rule_text='drop sccp any any -> $HOME_NET any (msg:"CAT1-CancelLoc"; map.opcode:3; sid:1000010;)',
    ),
]

# 4G Diameter CAT1 Rules (GSMA FS.19)
CAT1_DIAMETER_RULES = [
    CAT1Rule(
        rule_id="CAT1-DIA-001",
        sid=1000101,
        name="Unauthorized Cancel-Location-Request",
        description="CLR from unauthorized realm - subscriber detach attack",
        protocol="Diameter",
        generation="4G",
        command_code=317,  # Cancel-Location-Request
        attack_pattern="AP101",
        gsma_reference="FS.19 Section 6.2",
        severity="critical",
        rule_text='drop tcp any any -> any 3868 (msg:"CAT1-DIA-CLR"; diameter.cmd:317; sid:1000101;)',
    ),
    CAT1Rule(
        rule_id="CAT1-DIA-002",
        sid=1000102,
        name="Unauthorized Insert-Subscriber-Data-Request",
        description="IDR from unauthorized realm - profile manipulation",
        protocol="Diameter",
        generation="4G",
        command_code=319,  # Insert-Subscriber-Data-Request
        attack_pattern="AP102",
        gsma_reference="FS.19 Section 6.3",
        severity="critical",
        rule_text='drop tcp any any -> any 3868 (msg:"CAT1-DIA-IDR"; diameter.cmd:319; sid:1000102;)',
    ),
    CAT1Rule(
        rule_id="CAT1-DIA-003",
        sid=1000103,
        name="Unauthorized Delete-Subscriber-Data-Request",
        description="DSR from unauthorized realm - profile deletion",
        protocol="Diameter",
        generation="4G",
        command_code=320,  # Delete-Subscriber-Data-Request
        attack_pattern="AP103",
        gsma_reference="FS.19 Section 6.3",
        severity="critical",
        rule_text='drop tcp any any -> any 3868 (msg:"CAT1-DIA-DSR"; diameter.cmd:320; sid:1000103;)',
    ),
    CAT1Rule(
        rule_id="CAT1-DIA-004",
        sid=1000104,
        name="Unauthorized Reset-Request",
        description="RSR from unauthorized realm - mass subscriber reset",
        protocol="Diameter",
        generation="4G",
        command_code=322,  # Reset-Request
        attack_pattern="AP104",
        gsma_reference="FS.19 Section 6.4",
        severity="critical",
        rule_text='drop tcp any any -> any 3868 (msg:"CAT1-DIA-RSR"; diameter.cmd:322; sid:1000104;)',
    ),
    CAT1Rule(
        rule_id="CAT1-DIA-005",
        sid=1000105,
        name="Unauthorized Purge-UE-Request from VPLMN",
        description="PUR from visited network - unauthorized purge",
        protocol="Diameter",
        generation="4G",
        command_code=321,  # Purge-UE-Request
        attack_pattern="AP105",
        gsma_reference="FS.19 Section 6.5",
        severity="high",
        rule_text='drop tcp any any -> any 3868 (msg:"CAT1-DIA-PUR"; diameter.cmd:321; sid:1000105;)',
    ),
]

# 4G GTP-C CAT1 Rules
CAT1_GTPC_RULES = [
    CAT1Rule(
        rule_id="CAT1-GTP-001",
        sid=1000201,
        name="Unauthorized Delete-Session-Request",
        description="Delete Session from unauthorized source - session hijack",
        protocol="GTP-C",
        generation="4G",
        message_type=36,  # Delete Session Request
        attack_pattern="AP201",
        gsma_reference="FS.19 Section 7.1",
        severity="high",
        rule_text='drop udp any any -> any 2123 (msg:"CAT1-GTP-DelSession"; gtp.type:36; sid:1000201;)',
    ),
    CAT1Rule(
        rule_id="CAT1-GTP-002",
        sid=1000202,
        name="Unauthorized Modify-Bearer-Request",
        description="Modify Bearer from unauthorized source - traffic redirect",
        protocol="GTP-C",
        generation="4G",
        message_type=34,  # Modify Bearer Request
        attack_pattern="AP202",
        gsma_reference="FS.19 Section 7.2",
        severity="high",
        rule_text='drop udp any any -> any 2123 (msg:"CAT1-GTP-ModBearer"; gtp.type:34; sid:1000202;)',
    ),
    CAT1Rule(
        rule_id="CAT1-GTP-003",
        sid=1000203,
        name="GTP-in-GTP Tunneling Attack",
        description="Nested GTP tunnel detected - encapsulation attack",
        protocol="GTP-C",
        generation="4G",
        message_type=32,  # Create Session with nested GTP
        attack_pattern="AP203",
        gsma_reference="FS.19 Section 7.3",
        severity="critical",
        rule_text='drop udp any any -> any 2123 (msg:"CAT1-GTP-Nested"; content:"|34 ff|"; sid:1000203;)',
    ),
]

# ============================================================================
# CAT2 Rules — IR.21 Contextual Validation
# ============================================================================

@dataclass
class CAT2Rule:
    """Category 2 rule for contextual validation."""
    rule_id: str
    name: str
    description: str
    protocol: str
    generation: str
    procedure: str
    direction: str  # INBOUND, OUTBOUND
    ir21_checks: list[str]  # List of IR.21 fields to validate
    validation_logic: str
    gsma_reference: str = ""
    severity: str = "high"
    enabled: bool = True


CAT2_RULES = [
    # 3G MAP CAT2 Rules
    CAT2Rule(
        rule_id="CAT2-MAP-001",
        name="UpdateLocation Partner Validation",
        description="Validate UpdateLocation against IR.21 roaming agreement",
        protocol="MAP",
        generation="3G",
        procedure="UpdateLocation",
        direction="INBOUND",
        ir21_checks=["partner_gt", "mcc_mnc", "agreement_status"],
        validation_logic="source_gt IN ir21.partner_gt_list AND ir21.agreement_status = 'ACTIVE'",
        gsma_reference="IR.21 Section 4.2",
    ),
    CAT2Rule(
        rule_id="CAT2-MAP-002",
        name="SendAuthenticationInfo Partner Validation",
        description="Validate SAI request against IR.21 partner list",
        protocol="MAP",
        generation="3G",
        procedure="SendAuthenticationInfo",
        direction="INBOUND",
        ir21_checks=["partner_gt", "authorized_procedures"],
        validation_logic="source_gt IN ir21.partner_gt_list AND 'SAI' IN ir21.authorized_procedures",
        gsma_reference="IR.21 Section 4.3",
    ),
    CAT2Rule(
        rule_id="CAT2-MAP-003",
        name="ProvideRoamingNumber Partner Validation",
        description="Validate PRN against IR.21 voice roaming agreement",
        protocol="MAP",
        generation="3G",
        procedure="ProvideRoamingNumber",
        direction="INBOUND",
        ir21_checks=["partner_gt", "voice_roaming_enabled"],
        validation_logic="source_gt IN ir21.partner_gt_list AND ir21.voice_roaming = true",
        gsma_reference="IR.21 Section 4.4",
    ),
    CAT2Rule(
        rule_id="CAT2-MAP-004",
        name="SendRoutingInfoForSM SMSC Validation",
        description="Validate SRI-SM source against known SMSC list",
        protocol="MAP",
        generation="3G",
        procedure="SendRoutingInfoForSM",
        direction="INBOUND",
        ir21_checks=["smsc_gt_list", "sms_interworking"],
        validation_logic="source_gt IN ir21.smsc_gt_list AND ir21.sms_interworking = true",
        gsma_reference="IR.21 Section 4.5",
    ),
    
    # 4G Diameter CAT2 Rules
    CAT2Rule(
        rule_id="CAT2-DIA-001",
        name="Update-Location-Request Realm Validation",
        description="Validate ULR Origin-Realm against IR.21",
        protocol="Diameter",
        generation="4G",
        procedure="Update-Location-Request",
        direction="INBOUND",
        ir21_checks=["origin_realm", "diameter_peers", "lte_roaming_enabled"],
        validation_logic="origin_realm IN ir21.diameter_realms AND ir21.lte_roaming = true",
        gsma_reference="IR.21 Section 5.2",
    ),
    CAT2Rule(
        rule_id="CAT2-DIA-002",
        name="Authentication-Information-Request Validation",
        description="Validate AIR against authorized peers",
        protocol="Diameter",
        generation="4G",
        procedure="Authentication-Information-Request",
        direction="INBOUND",
        ir21_checks=["origin_realm", "origin_host", "authorized_applications"],
        validation_logic="origin_realm IN ir21.diameter_realms AND 'S6a' IN ir21.applications",
        gsma_reference="IR.21 Section 5.3",
    ),
    CAT2Rule(
        rule_id="CAT2-DIA-003",
        name="Notify-Request IMSI Validation",
        description="Validate NOR IMSI prefix against partner MCC/MNC",
        protocol="Diameter",
        generation="4G",
        procedure="Notify-Request",
        direction="INBOUND",
        ir21_checks=["imsi_prefix", "partner_mcc_mnc"],
        validation_logic="imsi[:5] MATCHES ir21.partner_mcc_mnc",
        gsma_reference="IR.21 Section 5.4",
    ),
    
    # 4G GTP-C CAT2 Rules
    CAT2Rule(
        rule_id="CAT2-GTP-001",
        name="Create-Session-Request APN Validation",
        description="Validate CSR APN against IR.21 allowed APNs",
        protocol="GTP-C",
        generation="4G",
        procedure="Create-Session-Request",
        direction="INBOUND",
        ir21_checks=["apn_list", "data_roaming_enabled"],
        validation_logic="apn IN ir21.allowed_apns AND ir21.data_roaming = true",
        gsma_reference="IR.21 Section 6.2",
    ),
    CAT2Rule(
        rule_id="CAT2-GTP-002",
        name="Create-Session-Request Serving-Network Validation",
        description="Validate serving network MCC/MNC against partner",
        protocol="GTP-C",
        generation="4G",
        procedure="Create-Session-Request",
        direction="INBOUND",
        ir21_checks=["serving_network", "partner_plmn_list"],
        validation_logic="serving_network IN ir21.partner_plmn_list",
        gsma_reference="IR.21 Section 6.3",
    ),

    # 3G SS7/SCCP CAT2 Rules (IR.21 routing / SCCP GT)
    CAT2Rule(
        rule_id="CAT2-SCCP-001",
        name="SCCP Calling GT vs IR.21 GT Range",
        description="Validate SCCP calling GT against IR.21 network-node GT ranges",
        protocol="SCCP",
        generation="3G",
        procedure="UDT",
        direction="INBOUND",
        ir21_checks=["partner_gt", "sccp_gt_range", "agreement_status"],
        validation_logic="calling_gt IN ir21.gt_prefixes AND ir21.agreement_status = 'ACTIVE'",
        gsma_reference="IR.21 Section 4 Routing Information",
    ),
    CAT2Rule(
        rule_id="CAT2-MAP-005",
        name="MAP Application Context vs IR.21 MAP Section",
        description="Validate MAP procedure against IR.21 MAP version declarations",
        protocol="MAP",
        generation="3G",
        procedure="UpdateLocation",
        direction="INBOUND",
        ir21_checks=["map_version", "partner_gt", "authorized_procedures"],
        validation_logic="'networkLocUp' IN ir21.map_contexts AND source_gt IN ir21.gt_prefixes",
        gsma_reference="IR.21 Section 8/10 MAP",
    ),
    CAT2Rule(
        rule_id="CAT2-CAP-001",
        name="CAMEL CAP Version vs IR.21 CAMEL Info",
        description="Validate inbound CAP against IR.21 gsmSSF/MSC CAP versions and SCP GTs",
        protocol="CAP",
        generation="3G",
        procedure="InitialDP",
        direction="INBOUND",
        ir21_checks=["cap_version", "scp_gt_list", "voice_roaming_enabled"],
        validation_logic="cap_version IN ir21.cap_versions AND scp_gt IN ir21.scp_gts",
        gsma_reference="IR.21 Section 15 CAMEL INFO",
    ),

    # 4G Diameter LTE roaming (IR.21 Section 20)
    CAT2Rule(
        rule_id="CAT2-DIA-004",
        name="S6a DEA FQDN vs IR.21 LTE Roaming",
        description="Validate Diameter Edge Agent FQDN/IP against IR.21 LTE roaming section",
        protocol="Diameter",
        generation="4G",
        procedure="Authentication-Information-Request",
        direction="INBOUND",
        ir21_checks=["dea_fqdn", "origin_realm", "lte_roaming_enabled"],
        validation_logic="origin_host IN ir21.dea_fqdns AND ir21.lte_roaming = true AND ir21.s6a_supported = true",
        gsma_reference="IR.21 Section 20 LTE Roaming Information",
    ),
    CAT2Rule(
        rule_id="CAT2-DIA-005",
        name="Purge-UE-Request Realm Validation",
        description="Validate inbound PUR Origin-Realm against IR.21 Diameter peers",
        protocol="Diameter",
        generation="4G",
        procedure="Purge-UE-Request",
        direction="INBOUND",
        ir21_checks=["origin_realm", "diameter_peers", "lte_roaming_enabled"],
        validation_logic="origin_realm IN ir21.diameter_realms AND ir21.lte_roaming = true",
        gsma_reference="IR.21 Section 20 / FS.19",
    ),

    # 4G GTP IP-range (IR.21 Section 16/17)
    CAT2Rule(
        rule_id="CAT2-GTP-003",
        name="GTP Source IP vs IR.21 IP Roaming Range",
        description="Validate GTP-C source against IR.21 IP roaming / GRX address ranges",
        protocol="GTP-C",
        generation="4G",
        procedure="Create-Session-Request",
        direction="INBOUND",
        ir21_checks=["gtp_ip_range", "data_roaming_enabled", "gtp_version"],
        validation_logic="source_ip IN ir21.ip_ranges AND ir21.data_roaming = true",
        gsma_reference="IR.21 Section 16/17 Packet Data / IP Roaming",
    ),
]

# ============================================================================
# CAT3 Rules — AI-Driven Behavioral Analysis
# ============================================================================

@dataclass
class CAT3Rule:
    """Category 3 rule for AI-driven behavioral analysis."""
    rule_id: str
    name: str
    description: str
    category: str  # CAT3.1, CAT3.2
    protocol: str
    generation: str
    analysis_type: str  # sequence, velocity, frequency, pattern
    parameters: dict[str, Any] = field(default_factory=dict)
    ai_model: str = "rule_based"  # rule_based, ml_classifier, anomaly_detection
    threshold: float = 0.8
    gsma_reference: str = ""
    severity: str = "medium"
    enabled: bool = True


CAT3_RULES = [
    # CAT3.1 — Sequence/Authorization Validation
    CAT3Rule(
        rule_id="CAT3.1-001",
        name="Mobility Without Authentication",
        description="Location update without prior authentication exchange",
        category="CAT3.1",
        protocol="MAP",
        generation="3G",
        analysis_type="sequence",
        parameters={
            "required_prior_event": "SendAuthenticationInfo",
            "max_gap_seconds": 1800,
            "trigger_event": "UpdateLocation",
        },
        ai_model="rule_based",
        gsma_reference="FS.11 Section 7.1",
    ),
    CAT3Rule(
        rule_id="CAT3.1-002",
        name="Diameter ULR Without AIR",
        description="Update-Location without prior Authentication-Info exchange",
        category="CAT3.1",
        protocol="Diameter",
        generation="4G",
        analysis_type="sequence",
        parameters={
            "required_prior_event": "Authentication-Information-Request",
            "max_gap_seconds": 1800,
            "trigger_event": "Update-Location-Request",
        },
        ai_model="rule_based",
        gsma_reference="FS.19 Section 8.1",
    ),
    CAT3Rule(
        rule_id="CAT3.1-003",
        name="GTP Session Without Diameter Auth",
        description="Create-Session without HSS authentication",
        category="CAT3.1",
        protocol="GTP-C",
        generation="4G",
        analysis_type="sequence",
        parameters={
            "required_prior_event": "Authentication-Information-Answer",
            "max_gap_seconds": 300,
            "trigger_event": "Create-Session-Request",
        },
        ai_model="rule_based",
        gsma_reference="FS.19 Section 8.2",
    ),
    CAT3Rule(
        rule_id="CAT3.1-004",
        name="SMS-MO Without Registration",
        description="Outgoing SMS without active registration",
        category="CAT3.1",
        protocol="MAP",
        generation="3G",
        analysis_type="sequence",
        parameters={
            "required_prior_event": "UpdateLocation",
            "max_gap_seconds": 86400,
            "trigger_event": "MO-ForwardSM",
        },
        ai_model="rule_based",
    ),
    
    # CAT3.2 — Velocity/Behavioral Analysis
    CAT3Rule(
        rule_id="CAT3.2-001",
        name="Impossible Travel Detection",
        description="Subscriber location change faster than physically possible",
        category="CAT3.2",
        protocol="MAP",
        generation="3G/4G",
        analysis_type="velocity",
        parameters={
            "max_velocity_kmh": 1000,
            "min_distance_km": 100,
            "min_time_gap_seconds": 60,
        },
        ai_model="rule_based",
        gsma_reference="FS.11 Section 7.2",
        threshold=0.95,
    ),
    CAT3Rule(
        rule_id="CAT3.2-002",
        name="Rapid PLMN Switching",
        description="Subscriber switching between PLMNs too frequently",
        category="CAT3.2",
        protocol="Diameter",
        generation="4G",
        analysis_type="frequency",
        parameters={
            "max_switches_per_hour": 10,
            "window_seconds": 3600,
            "distinct_plmns_threshold": 5,
        },
        ai_model="anomaly_detection",
        gsma_reference="FS.19 Section 8.3",
    ),
    CAT3Rule(
        rule_id="CAT3.2-003",
        name="Abnormal Location Update Frequency",
        description="Location updates at unusual frequency for stationary subscriber",
        category="CAT3.2",
        protocol="MAP",
        generation="3G",
        analysis_type="frequency",
        parameters={
            "max_updates_per_hour": 60,
            "stationary_threshold_km": 1,
            "window_seconds": 3600,
        },
        ai_model="ml_classifier",
    ),
    CAT3Rule(
        rule_id="CAT3.2-004",
        name="SIM Cloning Detection",
        description="Same IMSI active in multiple locations simultaneously",
        category="CAT3.2",
        protocol="MAP",
        generation="3G/4G",
        analysis_type="pattern",
        parameters={
            "simultaneous_threshold_seconds": 60,
            "min_distance_km": 50,
        },
        ai_model="rule_based",
        gsma_reference="FS.11 Section 7.3",
        severity="critical",
    ),
    CAT3Rule(
        rule_id="CAT3.2-005",
        name="Silent SMS Flood Detection",
        description="High volume of Type-0 SMS to single subscriber",
        category="CAT3.2",
        protocol="MAP",
        generation="3G",
        analysis_type="frequency",
        parameters={
            "max_silent_sms_per_hour": 5,
            "window_seconds": 3600,
            "pid_type0": True,
        },
        ai_model="rule_based",
        severity="high",
    ),
    CAT3Rule(
        rule_id="CAT3.2-006",
        name="Diameter Probing Detection",
        description="Systematic AIR requests for sequential IMSIs",
        category="CAT3.2",
        protocol="Diameter",
        generation="4G",
        analysis_type="pattern",
        parameters={
            "sequential_imsi_threshold": 5,
            "window_seconds": 300,
            "source_realm_tracking": True,
        },
        ai_model="anomaly_detection",
        gsma_reference="FS.19 Section 8.4",
        severity="high",
    ),
    CAT3Rule(
        rule_id="CAT3.2-007",
        name="GTP Tunnel Anomaly",
        description="Unusual GTP tunnel creation patterns",
        category="CAT3.2",
        protocol="GTP-C",
        generation="4G",
        analysis_type="pattern",
        parameters={
            "max_tunnels_per_subscriber": 5,
            "unusual_teid_pattern": True,
            "zero_volume_tunnel_threshold": 10,
        },
        ai_model="ml_classifier",
    ),
    CAT3Rule(
        rule_id="CAT3.2-008",
        name="Roaming Fraud Pattern",
        description="Subscriber behavior matching known roaming fraud patterns",
        category="CAT3.2",
        protocol="Diameter",
        generation="4G",
        analysis_type="pattern",
        parameters={
            "high_value_services": ["premium_sms", "data_roaming"],
            "velocity_anomaly": True,
            "new_imei_detection": True,
        },
        ai_model="ml_classifier",
        severity="high",
    ),
]

# ============================================================================
# IR.21 Partner Database (Sample Data)
# ============================================================================

@dataclass
class IR21Partner:
    """IR.21 roaming partner — SS7, Diameter, GTP, CAMEL fields from the RAEX template."""
    partner_id: str
    operator_name: str
    country: str
    mcc: str
    mnc: str
    tadig_code: str
    document_id: str = ""
    # IR.21 §4 Routing — SS7/SCCP GT ranges
    gt_prefixes: list[str] = field(default_factory=list)
    msisdn_prefixes: list[str] = field(default_factory=list)
    mgt_cc_nc: str = ""
    # IR.21 §9/13 Network elements
    smsc_gts: list[str] = field(default_factory=list)
    hlr_gts: list[str] = field(default_factory=list)
    hss_gts: list[str] = field(default_factory=list)
    msc_gts: list[str] = field(default_factory=list)
    sgsn_gts: list[str] = field(default_factory=list)
    scp_gts: list[str] = field(default_factory=list)
    # IR.21 §8/10 MAP
    map_versions: list[str] = field(default_factory=list)
    map_contexts: list[str] = field(default_factory=list)
    # IR.21 §15 CAMEL
    cap_versions: list[str] = field(default_factory=list)
    # IR.21 §20 LTE / Diameter
    origin_realm: str = ""
    origin_hosts: list[str] = field(default_factory=list)
    diameter_peers: list[str] = field(default_factory=list)
    diameter_applications: list[str] = field(default_factory=list)
    dea_fqdns: list[str] = field(default_factory=list)
    dea_ips: list[str] = field(default_factory=list)
    s6a_supported: bool = True
    # IR.21 §16/17 GTP / IP roaming
    pgw_addresses: list[str] = field(default_factory=list)
    sgw_addresses: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    gtp_version: str = "GTPv2"
    apn_operator_id: str = ""
    # Roaming agreements
    voice_roaming: bool = True
    sms_roaming: bool = True
    data_roaming: bool = True
    lte_roaming: bool = True
    volte_roaming: bool = False
    # Authorized services
    allowed_apns: list[str] = field(default_factory=list)
    authorized_procedures: list[str] = field(default_factory=list)
    # Agreement status
    agreement_status: str = "ACTIVE"
    agreement_start: str = ""
    agreement_end: str = ""


# Sample IR.21 Partner Data (Middle East & GCC Region)
IR21_PARTNERS = [
    IR21Partner(
        partner_id="KWTZN",
        operator_name="Zain Kuwait",
        country="Kuwait",
        mcc="419",
        mnc="02",
        tadig_code="KWTZN",
        gt_prefixes=["96596", "96597"],
        smsc_gts=["96596000100"],
        hlr_gts=["96596000001"],
        document_id="IR.21 KWTZN",
        origin_realm="zain.com.kw",
        origin_hosts=["mme1.zain.com.kw", "mme2.zain.com.kw"],
        diameter_peers=["hss.zain.com.kw", "dra.zain.com.kw"],
        diameter_applications=["S6a", "S6d", "SWx"],
        dea_fqdns=["dra.zain.com.kw", "mme1.zain.com.kw"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp", "InfoRetrieval", "roamingNumberEnquiry"],
        cap_versions=["CAPv2", "CAPv3"],
        msisdn_prefixes=["96596", "96597"],
        mgt_cc_nc="965 96",
        ip_ranges=["37.36.0.0/16"],
        gtp_version="GTPv2",
        allowed_apns=["internet", "wap", "mms"],
        authorized_procedures=["UL", "SAI", "PRN", "SRI-SM", "UpdateLocation", "SendAuthenticationInfo"],
        lte_roaming=True,
    ),
    IR21Partner(
        partner_id="KWTOO",
        operator_name="Ooredoo Kuwait",
        country="Kuwait",
        mcc="419",
        mnc="04",
        tadig_code="KWTOO",
        gt_prefixes=["96565", "96566"],
        smsc_gts=["96565000100"],
        hlr_gts=["96565000001"],
        document_id="IR.21 KWTOO",
        origin_realm="ooredoo.com.kw",
        origin_hosts=["mme.ooredoo.com.kw"],
        diameter_peers=["hss.ooredoo.com.kw"],
        diameter_applications=["S6a", "S6d"],
        dea_fqdns=["mme.ooredoo.com.kw"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp", "InfoRetrieval"],
        cap_versions=["CAPv2"],
        allowed_apns=["internet", "ooredoo.net"],
        authorized_procedures=["UL", "SAI", "PRN", "SRI-SM", "UpdateLocation", "SendAuthenticationInfo"],
        lte_roaming=True,
    ),
    IR21Partner(
        partner_id="SAUSTC",
        operator_name="STC Saudi Arabia",
        country="Saudi Arabia",
        mcc="420",
        mnc="01",
        tadig_code="SAUSTC",
        gt_prefixes=["96650", "96655"],
        smsc_gts=["96650000100"],
        hlr_gts=["96650000001"],
        document_id="IR.21 SAUSTC",
        origin_realm="stc.com.sa",
        origin_hosts=["mme1.stc.com.sa", "mme2.stc.com.sa"],
        diameter_peers=["hss.stc.com.sa", "dra.stc.com.sa"],
        diameter_applications=["S6a", "S6d", "Cx", "Sh"],
        dea_fqdns=["dra.stc.com.sa"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp", "InfoRetrieval", "subscribeDataMngt"],
        cap_versions=["CAPv2", "CAPv3"],
        allowed_apns=["jawalnet", "internet", "ims"],
        authorized_procedures=["UL", "SAI", "PRN", "SRI-SM", "PSI", "UpdateLocation", "SendAuthenticationInfo"],
        lte_roaming=True,
        volte_roaming=True,
    ),
    IR21Partner(
        partner_id="SAUMOB",
        operator_name="Mobily Saudi Arabia",
        country="Saudi Arabia",
        mcc="420",
        mnc="03",
        tadig_code="SAUMOB",
        document_id="IR.21 SAUMOB",
        gt_prefixes=["96654", "96656"],
        origin_realm="mobily.com.sa",
        origin_hosts=["mme.mobily.com.sa"],
        diameter_applications=["S6a"],
        dea_fqdns=["mme.mobily.com.sa"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp", "InfoRetrieval"],
        cap_versions=["CAPv2"],
        allowed_apns=["web1", "web2", "ims"],
        authorized_procedures=["UL", "SAI", "PRN", "UpdateLocation"],
        lte_roaming=True,
    ),
    IR21Partner(
        partner_id="AREDU",
        operator_name="du UAE",
        country="UAE",
        mcc="424",
        mnc="03",
        tadig_code="AREDU",
        document_id="IR.21 AREDU",
        gt_prefixes=["97155", "97158"],
        origin_realm="du.ae",
        origin_hosts=["mme1.du.ae", "mme2.du.ae"],
        diameter_applications=["S6a", "S6d"],
        dea_fqdns=["mme1.du.ae"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp"],
        cap_versions=["CAPv2", "CAPv3"],
        allowed_apns=["internet", "du"],
        authorized_procedures=["UL", "SAI", "PRN", "SRI-SM", "UpdateLocation"],
        lte_roaming=True,
    ),
    IR21Partner(
        partner_id="AREETC",
        operator_name="Etisalat UAE",
        country="UAE",
        mcc="424",
        mnc="02",
        tadig_code="AREETC",
        document_id="IR.21 AREETC",
        gt_prefixes=["97150", "97156"],
        origin_realm="etisalat.ae",
        origin_hosts=["mme.etisalat.ae"],
        diameter_applications=["S6a", "Cx"],
        dea_fqdns=["mme.etisalat.ae"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp", "InfoRetrieval"],
        cap_versions=["CAPv2", "CAPv3"],
        allowed_apns=["etisalat.ae", "internet", "mms"],
        authorized_procedures=["UL", "SAI", "PRN", "SRI-SM", "UpdateLocation"],
        lte_roaming=True,
        volte_roaming=True,
    ),
    IR21Partner(
        partner_id="QATOO",
        operator_name="Ooredoo Qatar",
        country="Qatar",
        mcc="427",
        mnc="01",
        tadig_code="QATOO",
        document_id="IR.21 QATOO",
        gt_prefixes=["97455", "97466"],
        origin_realm="ooredoo.qa",
        origin_hosts=["mme.ooredoo.qa"],
        diameter_applications=["S6a"],
        dea_fqdns=["mme.ooredoo.qa"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp"],
        cap_versions=["CAPv2"],
        allowed_apns=["internet", "ooredoo.net.qa"],
        authorized_procedures=["UL", "SAI", "PRN", "UpdateLocation"],
        lte_roaming=True,
    ),
    IR21Partner(
        partner_id="BAHMTC",
        operator_name="Batelco Bahrain",
        country="Bahrain",
        mcc="426",
        mnc="01",
        tadig_code="BAHMTC",
        document_id="IR.21 BAHMTC",
        gt_prefixes=["97336", "97339"],
        origin_realm="batelco.com.bh",
        origin_hosts=["mme.batelco.com.bh"],
        diameter_applications=["S6a"],
        dea_fqdns=["mme.batelco.com.bh"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp"],
        cap_versions=["CAPv2"],
        allowed_apns=["internet", "batelco.com"],
        authorized_procedures=["UL", "SAI", "PRN", "UpdateLocation"],
        lte_roaming=True,
    ),
    IR21Partner(
        partner_id="OMNTEL",
        operator_name="Omantel",
        country="Oman",
        mcc="422",
        mnc="02",
        tadig_code="OMNTEL",
        document_id="IR.21 OMNTEL",
        gt_prefixes=["96899", "96895"],
        origin_realm="omantel.om",
        origin_hosts=["mme.omantel.om"],
        diameter_applications=["S6a"],
        dea_fqdns=["mme.omantel.om"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp"],
        cap_versions=["CAPv2"],
        allowed_apns=["internet", "omantel.net.om"],
        authorized_procedures=["UL", "SAI", "PRN", "UpdateLocation"],
        lte_roaming=True,
    ),
    # Real RAEX IR.21 document: data/ir21/MYSBC_Maxis_IR21.txt
    IR21Partner(
        partner_id="MYSBC",
        operator_name="Maxis Communications Berhad",
        country="Malaysia",
        mcc="502",
        mnc="12",
        tadig_code="MYSBC",
        document_id="IR.21 MYSBC",
        gt_prefixes=["6012", "6017"],
        msisdn_prefixes=["6012", "6017"],
        mgt_cc_nc="60 12",
        hss_gts=["60120000020", "60120000249", "60120000250"],
        msc_gts=["60120001445", "60120001446", "60120001451"],
        sgsn_gts=["60120001086", "60120001087"],
        smsc_gts=["60120000015"],
        scp_gts=["60120001056", "60120001408", "60120001606"],
        map_versions=["MAPv3"],
        map_contexts=["networkLocUp", "roamingNumberEnquiry", "InfoRetrieval", "subscribeDataMngt", "gprsLocationUpdate"],
        cap_versions=["CAPv1", "CAPv2", "CAPv3"],
        origin_realm="epc.mnc012.mcc502.3gppnetwork.org",
        origin_hosts=["s001.hkgdra001.aicent.grx", "s001.sindra001.aicent.grx"],
        diameter_peers=["s001.hkgdra001.aicent.grx", "s001.sindra001.aicent.grx"],
        diameter_applications=["S6a", "S6d"],
        dea_fqdns=["s001.hkgdra001.aicent.grx", "s001.sindra001.aicent.grx"],
        dea_ips=["216.200.79.132", "216.200.79.196"],
        s6a_supported=True,
        ip_ranges=["202.75.170.0/24", "202.75.138.0/24", "202.146.78.16/28"],
        gtp_version="GTPv1",
        apn_operator_id="mnc012.mcc502.gprs",
        allowed_apns=["internet", "maxis", "mms"],
        authorized_procedures=["UL", "SAI", "PRN", "SRI-SM", "UpdateLocation", "SendAuthenticationInfo", "Create-Session-Request"],
        lte_roaming=True,
        data_roaming=True,
        voice_roaming=True,
        sms_roaming=True,
    ),
]

# ============================================================================
# Helper Functions
# ============================================================================

def get_all_cat1_rules() -> list[CAT1Rule]:
    """Get all CAT1 rules."""
    return CAT1_MAP_RULES + CAT1_DIAMETER_RULES + CAT1_GTPC_RULES


def get_all_cat2_rules() -> list[CAT2Rule]:
    """Get all CAT2 rules."""
    return CAT2_RULES


def get_all_cat3_rules() -> list[CAT3Rule]:
    """Get all CAT3 rules."""
    return CAT3_RULES


def get_all_ir21_partners() -> list[IR21Partner]:
    """Get all IR.21 partners."""
    return IR21_PARTNERS


def get_partner_by_realm(realm: str) -> IR21Partner | None:
    """Lookup partner by Diameter realm."""
    realm_lower = realm.lower()
    for partner in IR21_PARTNERS:
        if partner.origin_realm.lower() == realm_lower:
            return partner
        if realm_lower.endswith('.' + partner.origin_realm.lower()):
            return partner
    return None


def get_partner_by_mccmnc(mcc: str, mnc: str) -> IR21Partner | None:
    """Lookup partner by MCC/MNC."""
    for partner in IR21_PARTNERS:
        if partner.mcc == mcc and partner.mnc == mnc:
            return partner
    return None


def get_partner_by_gt(gt: str) -> IR21Partner | None:
    """Lookup partner by Global Title prefix."""
    gt_clean = "".join(c for c in (gt or "") if c.isdigit())
    if not gt_clean:
        return None
    for partner in IR21_PARTNERS:
        for prefix in partner.gt_prefixes + partner.smsc_gts + partner.hlr_gts + partner.scp_gts:
            prefix_clean = "".join(c for c in prefix if c.isdigit())
            if prefix_clean and gt_clean.startswith(prefix_clean):
                return partner
    return None


def partner_to_context(p: IR21Partner) -> dict[str, Any]:
    """Serialize IR.21 partner as protocol-grouped contextual fields."""
    return {
        "partner_id": p.partner_id,
        "operator_name": p.operator_name,
        "country": p.country,
        "mcc": p.mcc,
        "mnc": p.mnc,
        "tadig_code": p.tadig_code,
        "document_id": p.document_id or f"IR.21 {p.tadig_code}",
        "agreement_status": p.agreement_status,
        "ss7": {
            "gt_prefixes": p.gt_prefixes,
            "msisdn_prefixes": p.msisdn_prefixes,
            "mgt_cc_nc": p.mgt_cc_nc,
            "smsc_gts": p.smsc_gts,
            "hlr_gts": p.hlr_gts,
            "hss_gts": p.hss_gts,
            "msc_gts": p.msc_gts,
            "sgsn_gts": p.sgsn_gts,
            "scp_gts": p.scp_gts,
            "map_versions": p.map_versions,
            "map_contexts": p.map_contexts,
            "cap_versions": p.cap_versions,
        },
        "diameter": {
            "origin_realm": p.origin_realm,
            "origin_hosts": p.origin_hosts,
            "diameter_peers": p.diameter_peers,
            "diameter_applications": p.diameter_applications,
            "dea_fqdns": p.dea_fqdns,
            "dea_ips": p.dea_ips,
            "s6a_supported": p.s6a_supported,
            "lte_roaming": p.lte_roaming,
        },
        "gtp": {
            "pgw_addresses": p.pgw_addresses,
            "sgw_addresses": p.sgw_addresses,
            "ip_ranges": p.ip_ranges,
            "gtp_version": p.gtp_version,
            "apn_operator_id": p.apn_operator_id,
            "allowed_apns": p.allowed_apns,
            "data_roaming": p.data_roaming,
        },
        "roaming": {
            "voice_roaming": p.voice_roaming,
            "sms_roaming": p.sms_roaming,
            "data_roaming": p.data_roaming,
            "lte_roaming": p.lte_roaming,
            "volte_roaming": p.volte_roaming,
            "authorized_procedures": p.authorized_procedures,
        },
    }


def ir21_rule_coverage() -> dict[str, Any]:
    """Summarize that every category has IR.21-contextual rules for SS7/Diameter/GTP."""
    cat2 = get_all_cat2_rules()
    by_proto: dict[str, list[str]] = {}
    missing_context = [
        r.rule_id for r in cat2 if r.enabled and not r.ir21_checks
    ]
    for r in cat2:
        by_proto.setdefault(r.protocol, []).append(r.rule_id)
    return {
        "cat1_rules": len(get_all_cat1_rules()),
        "cat2_rules": len(cat2),
        "cat3_rules": len(get_all_cat3_rules()),
        "partners": len(IR21_PARTNERS),
        "cat2_by_protocol": {k: len(v) for k, v in by_proto.items()},
        "cat2_contextual": all(bool(r.ir21_checks) for r in cat2 if r.enabled),
        "rules_missing_ir21_checks": missing_context,
        "protocols": sorted(by_proto.keys()),
    }
