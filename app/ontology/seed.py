"""Seed the 16-table ontology with plan examples + security patterns."""

from __future__ import annotations

from typing import Any

from app.database import postgres


def seed_ontology(*, mirror_graph: bool = True) -> dict[str, Any]:
    if not postgres.is_available():
        return {"ok": False, "error": "postgres unavailable"}
    _seed_config()
    _seed_runtime()
    _seed_security()
    result: dict[str, Any] = {"ok": True, "seeded": True}
    if mirror_graph:
        try:
            from app.ontology.mirror import mirror_all

            result["mirror"] = mirror_all()
        except Exception as exc:
            result["mirror"] = {"ok": False, "error": str(exc)}
    return result


def _exec(sql: str, params: tuple = ()) -> None:
    postgres.execute(sql, params)


def _seed_config() -> None:
    plmns = [
        ("NET001", "Example Mobile", "001", "01", "00101", "EXMPL", "HPLMN", "BIDIRECTIONAL", "OWN_NETWORK"),
        ("NET002", "Alpha Mobile", "262", "01", "26201", "ALPMN", "PARTNER", "INBOUND", "ACTIVE"),
        ("NET003", "Beta Telecom", "208", "01", "20801", "BETMN", "PARTNER", "INBOUND", "ACTIVE"),
        ("NET004", "Gamma Wireless", "234", "15", "23415", "GAMMN", "PARTNER", "BIDIRECTIONAL", "ACTIVE"),
    ]
    for row in plmns:
        _exec(
            """
            INSERT INTO plmn (network_id, operator_name, mcc, mnc, plmn_id, tadig, role,
                              supported_roaming_direction, agreement_status, source)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'SEED')
            ON CONFLICT (network_id) DO UPDATE SET
              operator_name = EXCLUDED.operator_name,
              agreement_status = EXCLUDED.agreement_status,
              updated_at = now()
            """,
            row,
        )

    configs = [
        ("RC003", "NET002", "LTE", "4G", "HOME_ROUTED", "Diameter/GTP"),
        ("RC004", "NET003", "LTE", "4G", "LOCAL_BREAKOUT", "Diameter/GTP"),
        ("RC006", "NET004", "5G", "5G", "HOME_ROUTED", "SBA/HTTP2/GTP"),
        ("RC001", "NET001", "LTE", "4G", "HOME_ROUTED", "Diameter/GTP"),
    ]
    for row in configs:
        _exec(
            """
            INSERT INTO roaming_configuration
              (config_id, network_id, technology, generation, roaming_mode, signaling_stack)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (config_id) DO NOTHING
            """,
            row,
        )

    elements = [
        ("NE001", "NET001", "Example Mobile", "001", "01", "HLR01", "HLR", "SS7/MAP", "0010100001", None, None, None),
        ("NE004", "NET001", "Example Mobile", "001", "01", "HSS01", "HSS", "Diameter", None, "hss01.epc.example", "epc.example", "198.51.100.10"),
        ("NE003", "NET001", "Example Mobile", "001", "01", "MME01", "MME", "Diameter/GTP-C", None, "mme01.epc.example", "epc.example", "10.10.30.10"),
        ("NE005", "NET002", "Alpha Mobile", "262", "01", "VLR01", "VLR", "SS7/MAP", "2620100001", None, None, None),
        ("NE008", "NET002", "Alpha Mobile", "262", "01", "MME01", "MME", "Diameter/GTP-C", None, "mme01.alpha.example", "epc.alphamobile.example", "192.0.2.11"),
        ("NE009", "NET001", "Example Mobile", "001", "01", "PGW01", "PGW", "GTP-C", None, None, None, "172.20.40.10"),
    ]
    for row in elements:
        _exec(
            """
            INSERT INTO network_element
              (network_element_id, plmn_id, operator_name, mcc, mnc, element_name, element_type,
               protocol, gt, diameter_host, diameter_realm, ip_address, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'ACTIVE')
            ON CONFLICT (network_element_id) DO NOTHING
            """,
            row,
        )

    for row in (
        ("DR002", "NET002", "RC003", "epc.alphamobile.example", "S6a", True),
        ("DR003", "NET003", "RC004", "epc.betatelecom.example", "S6a", True),
        ("DR001", "NET001", "RC001", "epc.example", "S6a", True),
    ):
        _exec(
            """
            INSERT INTO diameter_realm (realm_id, network_id, config_id, realm, application, authorized)
            VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (realm_id) DO NOTHING
            """,
            row,
        )

    for row in (
        ("DH001", "NE004", "NET001", "hss01.epc.example", "epc.example", "198.51.100.10", True),
        ("DH003", "NE008", "NET002", "mme01.alpha.example", "epc.alphamobile.example", "192.0.2.11", True),
    ):
        _exec(
            """
            INSERT INTO diameter_host
              (diameter_host_id, network_element_id, network_id, host_name, realm, ip_address, authorized)
            VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (diameter_host_id) DO NOTHING
            """,
            row,
        )

    for row in (
        ("GT001", "NET001", None, "0010100001", "NE001", "HLR", True),
        ("GT002", "NET002", "RC003", "2620100001", "NE005", "VLR", True),
    ):
        _exec(
            """
            INSERT INTO ss7_global_title
              (gt_id, network_id, config_id, global_title, network_element_id, role, authorized)
            VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (gt_id) DO NOTHING
            """,
            row,
        )

    for row in (
        ("SCCP001", "GT001", "NET001", "2-10-1", 6, "HLR", True),
        ("SCCP002", "GT002", "NET002", "3-10-1", 7, "VLR", True),
    ):
        _exec(
            """
            INSERT INTO sccp_address
              (sccp_id, gt_id, network_id, point_code, ssn, subsystem, authorized)
            VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (sccp_id) DO NOTHING
            """,
            row,
        )

    for row in (
        ("GW001", "NET001", "RC001", "H-PGW-01", "H-PGW", "198.51.100.51", "S8", True),
        ("GW003", "NET002", "RC003", "V-SGW-01", "V-SGW", "192.0.2.51", "S8", True),
    ):
        _exec(
            """
            INSERT INTO gtp_gateway
              (gateway_id, network_id, config_id, gateway_name, gateway_role, ip_address, interface, authorized)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (gateway_id) DO NOTHING
            """,
            row,
        )

    for row in (
        ("APN001", "RC001", "internet", "LTE", "HOME_ROUTED", True, "H-PGW", "ALLOW"),
        ("APN005", "RC001", "admin", "LTE", "HOME_ROUTED", False, "H-PGW", "BLOCK"),
    ):
        _exec(
            """
            INSERT INTO apn_policy
              (apn_policy_id, config_id, apn, technology, roaming_mode, allowed, expected_gateway_role, policy_action)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (apn_policy_id) DO NOTHING
            """,
            row,
        )

    # Widen validation_fields for full checklists
    try:
        _exec("ALTER TABLE message_policy ALTER COLUMN validation_fields TYPE VARCHAR(500)")
    except Exception:
        pass

    policies = [
        ("MP001", "RR001", "INBOUND", "SS7/MAP", "CAT2", "SendAuthenticationInfo", "STATIC",
         "OPCODE=56", "PARTNER_VALIDATION", "GT,MCC,MNC,IMSI", "ALERT"),
        ("MP002", "RR001", "INBOUND", "SS7/MAP", "CAT2", "UpdateLocation", "STATIC",
         "OPCODE=2", "PARTNER_IMSI_VALIDATION", "GT,SCCP,MCC,MNC,IMSI,VPLMN,roaming agreement", "ALERT"),
        ("MP003", "RR001", "INBOUND", "Diameter", "CAT2", "AuthenticationInformationRequest", "STATIC",
         "COMMAND_CODE=318", "PARTNER_VALIDATION", "Origin-Host,Origin-Realm,IMSI,Application-ID 16777251", "ALERT"),
        ("MP004", "RR001", "INBOUND", "Diameter", "CAT2", "UpdateLocationRequest", "STATIC",
         "COMMAND_CODE=316", "PARTNER_IMSI_VALIDATION",
         "Origin-Host,Origin-Realm,IMSI,MCC,MNC,VPLMN,roaming agreement,Application-ID 16777251", "BLOCK"),
        ("MP005", "RR001", "INBOUND", "GTP-C", "CAT2", "CreateSessionRequest", "STATIC",
         "MESSAGE_TYPE=32", "PARTNER_SESSION_VALIDATION",
         "Source-IP,IMSI,APN,Serving-Network,TEID,VPLMN", "ALERT"),
        ("MP006", "RR001", "INBOUND", "SS7/MAP", "CAT1", "PROHIBITED", "STATIC",
         "OPCODE=PROHIBITED_SET", "MESSAGE_TYPE_CHECK",
         "OPCODE; ATI; ProvideSubscriberInfo; InsertSubscriberData; SendIMSI", "BLOCK"),
        ("MP007", "RR001", "INBOUND", "Diameter", "CAT1", "PROHIBITED", "STATIC",
         "COMMAND_CODE=PROHIBITED_SET", "COMMAND_CODE_CHECK", "COMMAND_CODE", "BLOCK"),
        ("MP008", "RR001", "INBOUND", "GTP-C", "CAT1", "PROHIBITED", "STATIC",
         "MESSAGE_TYPE=PROHIBITED_SET", "MESSAGE_TYPE_CHECK", "MESSAGE_TYPE", "BLOCK"),
        ("MP009", "RR002", "OUTBOUND", "SS7/MAP", "CAT3.1", "MO-FSM", "STATIC",
         "OPCODE=44", "LOCATION_PLAUSIBILITY", "GT,IMSI,location,timestamp", "ALERT"),
        ("MP010", "RR002", "OUTBOUND", "SS7/MAP", "CAT3.1", "USSD", "STATIC",
         "OPCODE=59", "LOCATION_PLAUSIBILITY", "GT,IMSI,location,timestamp", "ALERT"),
        ("MP011", "RR002", "OUTBOUND", "SS7/MAP", "CAT3.2", "UpdateLocation", "STATIC",
         "OPCODE=2", "CONTEXT_PLAUSIBILITY", "IMSI,location,timestamp,velocity,GT,SCCP,VPLMN", "ALERT"),
        ("MP012", "RR002", "OUTBOUND", "Diameter", "CAT3.2", "UpdateLocationRequest", "STATIC",
         "COMMAND_CODE=316", "CONTEXT_PLAUSIBILITY",
         "IMSI,realm,host,location,session_state,Origin-Host,Origin-Realm", "ALERT"),
        ("MP013", "RR002", "OUTBOUND", "Diameter", "CAT3.2", "AuthenticationInformationRequest", "STATIC",
         "COMMAND_CODE=318", "CONTEXT_PLAUSIBILITY", "IMSI,realm,host,session_state,Origin-Host,Origin-Realm", "ALERT"),
        ("MP014", "RR002", "OUTBOUND", "GTP-C", "CAT3.2", "CreateSessionRequest", "STATIC",
         "MESSAGE_TYPE=32", "SESSION_CONTEXT", "IMSI,APN,TEID,Serving-Network,VPLMN,prior auth context", "ALERT"),
    ]
    for row in policies:
        _exec(
            """
            INSERT INTO message_policy
              (policy_id, relationship_id, direction, protocol, category, message_name,
               signature_type, signature, validation_type, validation_fields, action)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (policy_id) DO UPDATE SET
                relationship_id = EXCLUDED.relationship_id,
                direction = EXCLUDED.direction,
                protocol = EXCLUDED.protocol,
                category = EXCLUDED.category,
                message_name = EXCLUDED.message_name,
                signature_type = EXCLUDED.signature_type,
                signature = EXCLUDED.signature,
                validation_type = EXCLUDED.validation_type,
                validation_fields = EXCLUDED.validation_fields,
                action = EXCLUDED.action
            """,
            row,
        )


def _seed_runtime() -> None:
    _exec(
        """
        INSERT INTO subscriber_state
          (subscriber_id, imsi, hplmn_mcc_mnc, current_vplmn_mcc_mnc, location_node_gt,
           registration_state, auth_state, last_update)
        VALUES ('SUB001', '001010000000001', '001/01', '262/01', '2620100001',
                'REGISTERED', 'AUTHENTICATED', now())
        ON CONFLICT (subscriber_id) DO UPDATE SET
          auth_state = EXCLUDED.auth_state,
          registration_state = EXCLUDED.registration_state,
          last_update = now()
        """
    )
    _exec(
        """
        INSERT INTO session_state
          (session_id, imsi, hplmn_mcc, hplmn_mnc, vplmn_mcc, vplmn_mnc,
           roaming_direction, roaming_mode, protocol, apn, session_status, start_time)
        VALUES ('SES001', '001010000000001', '001', '01', '262', '01',
                'INBOUND', 'HOME_ROUTED', 'GTP', 'internet', 'ACTIVE', now())
        ON CONFLICT (session_id) DO NOTHING
        """
    )
    events = [
        ("EV001", "001010000000001", "Diameter", "AuthenticationInformationRequest", "NE008", "192.0.2.11", "mme01.alpha.example", "epc.alphamobile.example", "262", "01"),
        ("EV002", "001010000000001", "Diameter", "UpdateLocationRequest", "NE008", "192.0.2.11", "mme01.alpha.example", "epc.alphamobile.example", "262", "01"),
        ("EV003", "001010000000001", "GTP-C", "CreateSessionRequest", "NE009", "172.20.20.10", None, None, "001", "01"),
        ("EV004", "001010000000001", "SS7/MAP", "SendAuthenticationInfo", "NE005", "262020000001", None, None, "001", "01"),
    ]
    for i, row in enumerate(events):
        _exec(
            """
            INSERT INTO signaling_event
              (event_id, imsi, event_time, protocol, message_name, origin_ne_id,
               source_address, origin_host, origin_realm, serving_mcc, serving_mnc)
            VALUES (%s,%s, now() - (%s || ' seconds')::interval, %s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            (row[0], row[1], str((len(events) - i) * 3), row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]),
        )
    for row in (
        ("REL001", "001010000000001", "EV001", "EV002", "Diameter→Diameter", 2.0, "AIR→ULR", True, "LOW"),
        ("REL002", "001010000000001", "EV002", "EV003", "Diameter→GTP-C", 3.0, "ULR→CreateSessionRequest", True, "LOW"),
        ("REL003", "001010000000001", "EV002", "EV004", "Diameter→SS7/MAP", 5.0, "ULR→ATI", False, "HIGH"),
    ):
        _exec(
            """
            INSERT INTO signaling_relationship
              (relationship_id, imsi, event_1_id, event_2_id, protocol_transition,
               time_delta_sec, event_transition, expected, risk)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (relationship_id) DO NOTHING
            """,
            row,
        )


def _seed_security() -> None:
    patterns = [
        ("AP001", "Authentication Vector Probing – Diameter", "Diameter/S6a", "CAT3.2",
         "AIR", "AIR→AIR→AIR...", "Authentication Vector Acquisition", "HIGH",
         "Origin-Host + IMSI", 300, "≥20 distinct IMSIs",
         "Same Origin-Host repeatedly requests authentication vectors for many unrelated IMSIs"),
        ("AP002", "Unauthorized Subscriber Registration Probing", "Diameter/S6a", "CAT3.2",
         "ULR", "ULR without expected preceding authentication/registration context",
         "Obtain subscriber/location/subscription information", "HIGH",
         "IMSI + Origin-Host", 120, "≥1 anomalous ULR",
         "ULR occurs without valid preceding context and/or expected subsequent mobility/session procedure"),
        ("AP003", "Authentication Vector Probing – SS7", "SS7/MAP", "CAT3.2",
         "SendAuthenticationInfo", "SAI→SAI→SAI...", "Obtain authentication vectors", "HIGH",
         "Calling-GT + IMSI", 300, "≥10",
         "Repeated SAI for same/multiple IMSIs without corresponding mobility/authentication activity"),
        ("AP004", "Location Update Abuse", "SS7/MAP", "CAT3.2",
         "UpdateLocation", "UL with mobility/context validation",
         "Trigger HLR processing / obtain subscriber information", "HIGH",
         "IMSI + GT + timestamp", 300, "≥1",
         "UL inconsistent with subscriber known location, timestamp, roaming state or mobility velocity"),
        ("AP005", "Subscriber Information Probing", "SS7/MAP", "CAT3.1",
         "ProvideSubscriberInfo", "Trigger→PSI", "Obtain subscriber status/location information", "MEDIUM",
         "IMSI + Calling-GT", 300, "≥5",
         "PSI appears without legitimate trigger or corresponding subscriber activity"),
        ("AP006", "Authentication-to-Session Anomaly", "Diameter + GTP-C", "CAT2/CAT3.2",
         "AIR", "AIR→ULR→CreateSessionRequest", "Establish unauthorized packet-data session", "CRITICAL",
         "IMSI + timestamp + Host + IP + TEID", 120, "≥1",
         "Authentication/registration sequence followed by GTP session from unauthorized gateway"),
        ("AP007", "Cross-Protocol Subscriber Probing", "SS7 + Diameter", "CAT2/CAT3.2",
         "SAI/AIR", "SAI→AIR→ULR", "Obtain subscriber/authentication information", "CRITICAL",
         "IMSI + timestamp + source identity", 300, "≥1",
         "Same IMSI queried through multiple signaling protocols without legitimate roaming trigger"),
        ("AP008", "Cross-Protocol Roaming Session Abuse", "SS7 + Diameter + GTP-C", "CAT2/CAT3.2",
         "SAI/AIR", "SAI→AIR→ULR→CreateSessionRequest", "Establish unauthorized roaming session", "CRITICAL",
         "IMSI + timestamp + GT + Host + Realm + IP + TEID", 300, "≥1",
         "Complete sequence contains unauthorized GT/Host/Realm/GTP gateway/APN or inconsistent roaming identity"),
        ("AP009", "GTP Session Without Signaling Context", "GTP-C", "CAT2/CAT3.2",
         "CreateSessionRequest", "CreateSessionRequest without expected preceding context",
         "Create unauthorized data session", "HIGH",
         "IMSI + TEID + source_IP", 120, "≥1",
         "GTP session creation occurs without corresponding authentication/registration/mobility state"),
        ("AP010", "Unauthorized APN/Routing Behavior", "GTP-C", "CAT2/CAT3.2",
         "CreateSessionRequest", "CreateSessionRequest→CreateSessionResponse",
         "Obtain unauthorized data service / bypass roaming routing policy", "HIGH",
         "IMSI + APN + TEID + source_IP", 120, "≥1",
         "APN, gateway or routing behavior differs from authorized Home Routing/LBO policy"),
    ]
    for row in patterns:
        _exec(
            """
            INSERT INTO attack_pattern
              (attack_pattern_id, attack_name, protocol_scope, category, initiating_message,
               sequence_definition, attack_objective, severity,
               correlation_key, time_window_sec, frequency_threshold, suspicious_condition)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (attack_pattern_id) DO UPDATE SET
              attack_name = EXCLUDED.attack_name,
              protocol_scope = EXCLUDED.protocol_scope,
              category = EXCLUDED.category,
              initiating_message = EXCLUDED.initiating_message,
              sequence_definition = EXCLUDED.sequence_definition,
              attack_objective = EXCLUDED.attack_objective,
              severity = EXCLUDED.severity,
              correlation_key = EXCLUDED.correlation_key,
              time_window_sec = EXCLUDED.time_window_sec,
              frequency_threshold = EXCLUDED.frequency_threshold,
              suspicious_condition = EXCLUDED.suspicious_condition
            """,
            row,
        )
    rules = [
        ("DR001", "AP001", "TEL-DIA-CAT3.2-AIR-VECTOR-PROBING", "Diameter/S6a", "CAT3.2",
         "CORRELATION",
         "Command-Code, Origin-Host, Origin-Realm, IMSI, timestamp",
         "AIR + same Origin-Host + ≥20 distinct IMSIs within 300s + no corresponding subscriber authentication context",
         "ALERT", "HIGH", 0.94, "TESTING",
         'alert ip any any -> any any (msg:"TEL-DIA-CAT3.2-AIR-VECTOR-PROBING"; sid:900001; rev:1;)'),
        ("DR002", "AP002", "TEL-DIA-CAT3.2-ULR-UNAUTHORIZED-CONTEXT", "Diameter/S6a", "CAT3.2",
         "TRANSACTION+CORRELATION",
         "Command-Code, Origin-Host, Origin-Realm, IMSI, HPLMN, VPLMN",
         "ULR + unauthorized Origin-Host/Realm OR missing valid authentication/registration context; Command-Code 316; Application-ID 16777251",
         "BLOCK", "HIGH", 0.93, "TESTING",
         'drop tcp any any -> any 3868 (msg:"TEL-DIA-CAT3.2-ULR-UNAUTHORIZED-CONTEXT"; sid:900002; rev:1; classtype:policy-violation;)'),
        ("DR003", "AP003", "TEL-SS7-CAT3.2-SAI-VECTOR-PROBING", "SS7/MAP", "CAT3.2",
         "CORRELATION",
         "MAP Opcode, Calling-GT, Called-GT, IMSI, timestamp",
         "SAI + same Calling-GT + repeated requests for ≥10 IMSIs within 300s",
         "ALERT", "HIGH", 0.94, "TESTING",
         'alert ip any any -> any any (msg:"TEL-SS7-CAT3.2-SAI-VECTOR-PROBING"; sid:900003; rev:1;)'),
        ("DR004", "AP004", "TEL-SS7-CAT3.2-UL-PLAUSIBILITY", "SS7/MAP", "CAT3.2",
         "CORRELATION",
         "MAP Opcode, GT, IMSI, timestamp, previous_location, current_location, MCC, MNC",
         "UL + authorized GT + impossible mobility velocity OR timestamp/location inconsistency",
         "ALERT", "HIGH", 0.88, "TESTING",
         'alert ip any any -> any any (msg:"TEL-SS7-CAT3.2-UL-PLAUSIBILITY"; sid:900004; rev:1;)'),
        ("DR005", "AP005", "TEL-SS7-CAT3.1-PSI-UNAUTHORIZED-QUERY", "SS7/MAP", "CAT3.1",
         "TRANSACTION+CORRELATION",
         "MAP Opcode, Calling-GT, Called-GT, IMSI, trigger_event",
         "PSI + no authorized preceding trigger + repeated PSI threshold exceeded",
         "ALERT", "MEDIUM", 0.90, "TESTING",
         'alert ip any any -> any any (msg:"TEL-SS7-CAT3.1-PSI-UNAUTHORIZED-QUERY"; sid:900005; rev:1;)'),
        ("DR006", "AP006", "TEL-MP-AUTH-TO-GTP-ANOMALY", "Diameter+GTP-C", "CAT2/CAT3.2",
         "CORRELATION",
         "IMSI, Command-Code, Origin-Host, Realm, GTP Message-Type, source_IP, TEID, timestamp",
         "AIR→ULR→CreateSessionRequest within 120s + GTP source gateway unauthorized OR session identity inconsistent",
         "BLOCK", "CRITICAL", 0.96, "PRODUCTION",
         'drop udp any any -> any 2123 (msg:"TEL-MP-AUTH-TO-GTP-ANOMALY"; sid:900006; rev:1; classtype:policy-violation;)'),
        ("DR007", "AP007", "TEL-MP-SS7-DIA-SUBSCRIBER-PROBING", "SS7+Diameter", "CAT2/CAT3.2",
         "CORRELATION",
         "IMSI, GT, SCCP, Command-Code, Origin-Host, Realm, timestamp",
         "SAI/AIR→ULR for same IMSI within 300s + no legitimate mobility/roaming context",
         "ALERT", "CRITICAL", 0.92, "TESTING",
         'alert ip any any -> any any (msg:"TEL-MP-SS7-DIA-SUBSCRIBER-PROBING"; sid:900007; rev:1;)'),
        ("DR008", "AP008", "TEL-MP-SS7-DIA-GTP-ROAMING-ABUSE", "SS7+Diameter+GTP-C", "CAT2/CAT3.2",
         "CORRELATION",
         "IMSI, GT, SCCP, Command-Code, Host, Realm, GTP Message-Type, source_IP, APN, TEID, timestamp",
         "SAI/AIR→ULR→CreateSessionRequest within 300s + unauthorized signaling identity OR gateway OR APN",
         "BLOCK", "CRITICAL", 0.97, "PRODUCTION",
         'drop ip any any -> any any (msg:"TEL-MP-SS7-DIA-GTP-ROAMING-ABUSE"; sid:900008; rev:1; classtype:policy-violation;)'),
        ("DR009", "AP009", "TEL-GTP-CAT2-SESSION-NO-CONTEXT", "GTP-C", "CAT2/CAT3.2",
         "CORRELATION",
         "Message-Type, IMSI, TEID, source_IP, destination_IP, timestamp",
         "CreateSessionRequest + no valid authentication/registration/mobility event for same IMSI within 120s",
         "ALERT", "HIGH", 0.91, "TESTING",
         'alert ip any any -> any any (msg:"TEL-GTP-CAT2-SESSION-NO-CONTEXT"; sid:900009; rev:1;)'),
        ("DR010", "AP010", "TEL-GTP-ROAMING-APN-ROUTING-VIOLATION", "GTP-C", "CAT2/CAT3.2",
         "TRANSACTION+CORRELATION",
         "Message-Type, IMSI, APN, TEID, source_IP, destination_IP, HPLMN, VPLMN, roaming_mode",
         "CreateSessionRequest + APN not permitted OR gateway not authorized OR routing inconsistent with HR/LBO",
         "ALERT", "HIGH", 0.95, "TESTING",
         'alert ip any any -> any any (msg:"TEL-GTP-ROAMING-APN-ROUTING-VIOLATION"; sid:900010; rev:1;)'),
    ]
    for row in rules:
        _exec(
            """
            INSERT INTO detection_rule
              (detection_rule_id, attack_pattern_id, rule_name, protocol, category,
               detection_scope, required_fields, rule_logic, action, severity, confidence,
               status, suricata_text, rule_version, implementation, validation_result)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'1.0','Suricata + Lua/Neo4j','PASSED')
            ON CONFLICT (detection_rule_id) DO UPDATE SET
              attack_pattern_id = EXCLUDED.attack_pattern_id,
              rule_name = EXCLUDED.rule_name,
              protocol = EXCLUDED.protocol,
              category = EXCLUDED.category,
              detection_scope = EXCLUDED.detection_scope,
              required_fields = EXCLUDED.required_fields,
              rule_logic = EXCLUDED.rule_logic,
              action = EXCLUDED.action,
              severity = EXCLUDED.severity,
              confidence = EXCLUDED.confidence,
              status = EXCLUDED.status,
              suricata_text = EXCLUDED.suricata_text,
              validation_result = EXCLUDED.validation_result
            """,
            row,
        )
