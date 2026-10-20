"""
CAT2 Detection Engine — Rules + IR.21 Contextual Validation

CAT2 applies two-level validation:
1. Protocol-policy validation (authorized procedures for direction)
2. Operator/roaming partner validation via IR.21 lookup

Decision: ALLOW or BLOCK
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from app.ids.decision import (
    Category,
    Decision,
    DecisionType,
    IR21Evidence,
    Protocol,
    RuleMatch,
    ValidationResult,
)


@dataclass
class PartnerRecord:
    """IR.21 partner record with SS7, Diameter, and GTP context."""
    partner_id: str
    operator_name: str = ""
    mcc: str = ""
    mnc: str = ""
    origin_realm: str = ""
    origin_host: str = ""
    source_gateways: list[str] = field(default_factory=list)
    authorized_procedures: list[str] = field(default_factory=list)
    expected_apn: list[str] = field(default_factory=list)
    serving_network_mcc_mnc: str = ""
    document_id: str = ""
    document_section: str = ""
    document_excerpt: str = ""
    agreement_status: str = "ACTIVE"
    # SS7 / SCCP / MAP / CAMEL
    gt_prefixes: list[str] = field(default_factory=list)
    smsc_gts: list[str] = field(default_factory=list)
    hlr_gts: list[str] = field(default_factory=list)
    scp_gts: list[str] = field(default_factory=list)
    map_versions: list[str] = field(default_factory=list)
    map_contexts: list[str] = field(default_factory=list)
    cap_versions: list[str] = field(default_factory=list)
    # Diameter / LTE
    origin_hosts: list[str] = field(default_factory=list)
    diameter_peers: list[str] = field(default_factory=list)
    diameter_applications: list[str] = field(default_factory=list)
    dea_fqdns: list[str] = field(default_factory=list)
    dea_ips: list[str] = field(default_factory=list)
    s6a_supported: bool = True
    lte_roaming: bool = True
    # GTP / packet
    ip_ranges: list[str] = field(default_factory=list)
    gtp_version: str = ""
    voice_roaming: bool = True
    sms_roaming: bool = True
    data_roaming: bool = True


# Authorized procedures by direction
AUTHORIZED_INBOUND_PROCEDURES = {
    "Diameter": [
        "Authentication-Information-Request",
        "Update-Location-Request",
        "Purge-UE-Request",
        "Notify-Request",
    ],
    "GTP-C": [
        "Create-Session-Request",
        "Delete-Session-Request",
        "Modify-Bearer-Request",
    ],
    "MAP": [
        "SendAuthenticationInfo",
        "UpdateLocation",
        "ProvideRoamingNumber",
        "SendRoutingInfoForSM",
    ],
    "SCCP": [
        "UDT",
        "XUDT",
    ],
    "CAP": [
        "InitialDP",
        "ApplyCharging",
        "RequestReportBCSMEvent",
    ],
}

AUTHORIZED_OUTBOUND_PROCEDURES = {
    "Diameter": [
        "Update-Location-Answer",
        "Authentication-Information-Answer",
        "Cancel-Location-Request",
        "Insert-Subscriber-Data-Request",
    ],
    "GTP-C": [
        "Create-Session-Response",
        "Delete-Session-Response",
    ],
    "MAP": [
        "SendAuthenticationInfoRes",
        "UpdateLocationRes",
    ],
}


class IR21Store:
    """
    IR.21 Document Store for partner lookups.
    
    Loads from:
    1. Predefined 3G/4G partner rules
    2. Postgres IR.21 tables (if available)
    """
    
    def __init__(self):
        self._records: dict[str, PartnerRecord] = {}
        self._realm_index: dict[str, str] = {}  # realm -> partner_id
        self._mccmnc_index: dict[str, str] = {}  # mcc+mnc -> partner_id
        self._gt_index: dict[str, str] = {}  # gt_prefix -> partner_id
        self._host_index: dict[str, str] = {}  # diameter host/fqdn -> partner_id
        self._load_predefined_partners()
        self._load_from_database()
    
    def _index_partner(self, record: PartnerRecord) -> None:
        """Index a partner for SS7 GT, Diameter realm/host, and MCC/MNC lookup."""
        self._records[record.partner_id] = record
        if record.origin_realm:
            self._realm_index[record.origin_realm.lower()] = record.partner_id
        if record.mcc and record.mnc:
            self._mccmnc_index[f"{record.mcc}{record.mnc}"] = record.partner_id
        for gt in record.gt_prefixes + record.smsc_gts + record.hlr_gts + record.scp_gts:
            gt_clean = "".join(c for c in gt if c.isdigit())
            if gt_clean:
                self._gt_index[gt_clean] = record.partner_id
        for host in record.origin_hosts + record.diameter_peers + record.dea_fqdns:
            if host:
                self._host_index[host.lower()] = record.partner_id
        if record.origin_host:
            self._host_index[record.origin_host.lower()] = record.partner_id
    
    def _load_predefined_partners(self) -> None:
        """Load predefined IR.21 partners from rules_3g4g."""
        try:
            from app.ids.rules_3g4g import get_all_ir21_partners
            
            for p in get_all_ir21_partners():
                record = PartnerRecord(
                    partner_id=p.partner_id,
                    operator_name=p.operator_name,
                    mcc=p.mcc,
                    mnc=p.mnc,
                    origin_realm=p.origin_realm,
                    origin_host=p.origin_hosts[0] if p.origin_hosts else "",
                    source_gateways=p.pgw_addresses + p.sgw_addresses + p.dea_ips,
                    authorized_procedures=p.authorized_procedures,
                    expected_apn=p.allowed_apns,
                    serving_network_mcc_mnc=f"{p.mcc}-{p.mnc}",
                    document_id=p.document_id or f"IR.21 {p.tadig_code}",
                    agreement_status=p.agreement_status,
                    gt_prefixes=list(p.gt_prefixes),
                    smsc_gts=list(p.smsc_gts),
                    hlr_gts=list(p.hlr_gts),
                    scp_gts=list(p.scp_gts),
                    map_versions=list(p.map_versions),
                    map_contexts=list(p.map_contexts),
                    cap_versions=list(p.cap_versions),
                    origin_hosts=list(p.origin_hosts),
                    diameter_peers=list(p.diameter_peers),
                    diameter_applications=list(p.diameter_applications),
                    dea_fqdns=list(p.dea_fqdns),
                    dea_ips=list(p.dea_ips),
                    s6a_supported=p.s6a_supported,
                    lte_roaming=p.lte_roaming,
                    ip_ranges=list(p.ip_ranges),
                    gtp_version=p.gtp_version,
                    voice_roaming=p.voice_roaming,
                    sms_roaming=p.sms_roaming,
                    data_roaming=p.data_roaming,
                )
                self._index_partner(record)
                    
            print(f"[IR21Store] Loaded {len(self._records)} predefined partners")
        except Exception as e:
            print(f"[IR21Store] Failed to load predefined partners: {e}")
    
    def _load_from_database(self) -> None:
        """Load IR.21 records from Postgres."""
        try:
            from app.database import postgres
            if not postgres.is_available():
                return
            
            # Load PLMN records
            rows = postgres.fetch_all("""
                SELECT network_id, operator_name, mcc, mnc, plmn_id, 
                       agreement_status, role
                FROM plmn
                WHERE agreement_status = 'ACTIVE'
            """)
            for row in rows:
                partner_id = row.get("network_id") or row.get("plmn_id") or ""
                if not partner_id or partner_id in self._records:
                    continue
                mcc = str(row.get("mcc", "") or "")
                mnc = str(row.get("mnc", "") or "")
                # Keep richer predefined IR.21 context (APNs, GTs, realms) for the same PLMN
                if mcc and mnc and f"{mcc}{mnc}" in self._mccmnc_index:
                    continue
                record = PartnerRecord(
                    partner_id=partner_id,
                    operator_name=row.get("operator_name", ""),
                    mcc=mcc,
                    mnc=mnc,
                    serving_network_mcc_mnc=f"{mcc}-{mnc}" if mcc and mnc else "",
                    document_id="IR.21",
                    agreement_status=row.get("agreement_status", "ACTIVE"),
                )
                self._index_partner(record)
            
            # Load Diameter realms
            realm_rows = postgres.fetch_all("""
                SELECT realm, network_id, authorized, application
                FROM diameter_realm
                WHERE authorized = true
            """)
            for row in realm_rows:
                realm = row.get("realm", "")
                network_id = row.get("network_id", "")
                if not realm:
                    continue
                realm_key = realm.lower()
                if realm_key in self._realm_index:
                    continue
                if network_id:
                    self._realm_index[realm_key] = network_id
                    if network_id in self._records:
                        if not self._records[network_id].origin_realm:
                            self._records[network_id].origin_realm = realm
        except Exception:
            pass  # Fallback to predefined partners
    
    def reload(self) -> dict[str, int]:
        """Clear and reload IR.21 partners (predefined + database)."""
        self._records.clear()
        self._realm_index.clear()
        self._mccmnc_index.clear()
        self._gt_index.clear()
        self._host_index.clear()
        self._load_predefined_partners()
        self._load_from_database()
        return self.get_stats()

    def add_partner(self, record: PartnerRecord) -> None:
        """Add a partner record."""
        self._index_partner(record)
    
    def lookup_by_realm(self, realm: str) -> PartnerRecord | None:
        """Lookup partner by Diameter Origin-Realm."""
        realm_lower = realm.lower()
        partner_id = self._realm_index.get(realm_lower)
        if partner_id:
            return self._records.get(partner_id)
        
        # Try suffix matching
        for stored_realm, pid in self._realm_index.items():
            if realm_lower.endswith('.' + stored_realm) or stored_realm.endswith('.' + realm_lower):
                return self._records.get(pid)
        
        return None
    
    def lookup_by_mccmnc(self, mcc: str, mnc: str) -> PartnerRecord | None:
        """Lookup partner by MCC/MNC."""
        key = f"{mcc}{mnc}"
        partner_id = self._mccmnc_index.get(key)
        return self._records.get(partner_id) if partner_id else None
    
    def lookup_by_imsi(self, imsi: str) -> PartnerRecord | None:
        """Lookup partner by IMSI prefix (MCC+MNC)."""
        if len(imsi) >= 5:
            mcc = imsi[:3]
            mnc = imsi[3:5]
            return self.lookup_by_mccmnc(mcc, mnc)
        return None
    
    def lookup_by_gt(self, gt: str) -> PartnerRecord | None:
        """Lookup partner by Global Title prefix."""
        gt_clean = "".join(c for c in (gt or "") if c.isdigit())
        if not gt_clean:
            return None
        # Longest prefix match
        best: PartnerRecord | None = None
        best_len = 0
        for prefix, partner_id in self._gt_index.items():
            if gt_clean.startswith(prefix) and len(prefix) > best_len:
                best = self._records.get(partner_id)
                best_len = len(prefix)
        return best
    
    def lookup_by_host(self, host: str) -> PartnerRecord | None:
        """Lookup partner by Diameter Origin-Host / DEA FQDN."""
        if not host:
            return None
        host_lower = host.lower()
        partner_id = self._host_index.get(host_lower)
        if partner_id:
            return self._records.get(partner_id)
        for stored, pid in self._host_index.items():
            if host_lower.endswith("." + stored) or stored.endswith("." + host_lower):
                return self._records.get(pid)
        return None
    
    def lookup(self, partner_id: str) -> PartnerRecord | None:
        """Direct lookup by partner ID."""
        return self._records.get(partner_id)
    
    def get_all_partners(self) -> list[PartnerRecord]:
        """Get all partner records."""
        return list(self._records.values())
    
    def get_stats(self) -> dict[str, int]:
        """Get store statistics."""
        return {
            "total_partners": len(self._records),
            "realms_indexed": len(self._realm_index),
            "mccmnc_indexed": len(self._mccmnc_index),
            "gt_indexed": len(self._gt_index),
            "hosts_indexed": len(self._host_index),
        }


class CAT2Engine:
    """
    CAT2 Contextual Validation Engine.
    
    Two-level validation:
    1. Protocol-policy: Is this procedure authorized for this direction?
    2. Partner validation: Does IR.21 record confirm this partner?
    
    Decision: ALLOW or BLOCK
    """
    
    def __init__(
        self,
        ir21_store: IR21Store | None = None,
        dry_run: bool = False,
    ):
        self.ir21_store = ir21_store or IR21Store()
        self.dry_run = dry_run
        self.authorized_inbound = AUTHORIZED_INBOUND_PROCEDURES
        self.authorized_outbound = AUTHORIZED_OUTBOUND_PROCEDURES
        self.rules = self._load_cat2_rules()

    @staticmethod
    def _load_cat2_rules():
        from app.ids.rules_3g4g import get_all_cat2_rules
        return [r for r in get_all_cat2_rules() if r.enabled]

    @staticmethod
    def _normalize_protocol(protocol: str) -> str:
        p = (protocol or "").strip()
        pu = p.upper().replace("_", "-")
        if pu in ("SS7", "SCCP", "TCAP"):
            return "SCCP" if pu != "TCAP" else "MAP"
        if pu == "MAP":
            return "MAP"
        if pu in ("CAP", "CAMEL"):
            return "CAP"
        if "DIAMETER" in pu or pu == "DIA":
            return "Diameter"
        if pu in ("GTP-C", "GTPC", "GTP"):
            return "GTP-C"
        if pu == "GTP-U":
            return "GTP-C"
        return p.title() if p else ""
    
    def inspect(self, message: dict[str, Any]) -> Decision:
        """
        Validate message using CAT2 rules + IR.21 context.
        
        Args:
            message: Parsed signaling message with:
                - protocol: Diameter, GTP-C, MAP
                - procedure: Procedure/command name
                - direction: INBOUND or OUTBOUND
                - origin_realm: Diameter Origin-Realm
                - origin_host: Diameter Origin-Host
                - imsi: Subscriber IMSI
                - serving_network: Serving network MCC/MNC
                - apn: Access Point Name
                - source_gateway: GTP source gateway IP
        
        Returns:
            Decision with ALLOW or BLOCK
        """
        start_time = time.perf_counter()
        stages: list[dict[str, Any]] = []
        checks: list[dict[str, Any]] = []
        
        # Extract fields
        protocol = self._normalize_protocol(str(message.get("protocol", "")))
        procedure = str(message.get("procedure", ""))
        direction = str(message.get("direction", "INBOUND")).upper()
        origin_realm = str(message.get("origin_realm", ""))
        origin_host = str(message.get("origin_host", ""))
        imsi = str(message.get("imsi") or message.get("subscriber_id", ""))
        serving_network = str(message.get("serving_network", ""))
        apn = str(message.get("apn", ""))
        source_gateway = str(message.get("source_gateway", ""))
        source = str(message.get("source", ""))
        destination = str(message.get("destination", ""))
        calling_gt = str(message.get("calling_gt") or message.get("global_title") or "")
        map_version = str(message.get("map_version", ""))
        cap_version = str(message.get("cap_version", ""))
        gtp_version = str(message.get("gtp_version", ""))
        
        imsi_masked = self._mask_imsi(imsi)
        
        # Stage 1: Extract procedure type
        stages.append({
            "stage": "extract_procedure",
            "status": "complete",
            "procedure": procedure,
            "protocol": protocol,
        })
        
        # Stage 2: Infer roaming direction
        stages.append({
            "stage": "infer_direction",
            "status": "complete",
            "direction": direction,
        })
        
        # Stage 3: Level 1 - Protocol-policy + matching CAT2 IR.21 rules
        matched_rules = self._match_cat2_rules(protocol, procedure, direction)
        rule_match = self._rule_to_match(matched_rules[0], protocol, calling_gt, origin_realm) if matched_rules else None
        authorized_procedures = (
            self.authorized_inbound.get(protocol, [])
            if direction == "INBOUND"
            else self.authorized_outbound.get(protocol, [])
        )
        
        procedure_authorized = bool(matched_rules) or self._procedure_matches(
            procedure, authorized_procedures
        )
        checks.append({
            "check": "authorized_procedure",
            "procedure": procedure,
            "direction": direction,
            "authorized": procedure_authorized,
            "matched_rules": [r.rule_id for r in matched_rules],
            "allowed_procedures": authorized_procedures[:5],
        })
        
        stages.append({
            "stage": "protocol_policy_check",
            "status": "pass" if procedure_authorized else "fail",
            "authorized": procedure_authorized,
        })
        
        if not procedure_authorized:
            # BLOCK: Unauthorized procedure
            processing_time = (time.perf_counter() - start_time) * 1000
            return self._make_decision(
                decision_type=DecisionType.BLOCK,
                protocol=protocol,
                procedure=procedure,
                direction=direction,
                origin_realm=origin_realm,
                origin_host=origin_host,
                imsi_masked=imsi_masked,
                source=source,
                destination=destination,
                validation=ValidationResult(
                    authorized_procedure=False,
                    partner_found_in_ir21=False,
                    parameters_consistent=False,
                    checks=checks,
                ),
                reason=f"Unauthorized procedure '{procedure}' for {direction} {protocol}",
                stages=stages,
                processing_time=processing_time,
                rule_match=rule_match,
            )
        
        # Stage 4: Extract partner identity
        partner_id = self._extract_partner_identity(message, protocol)
        stages.append({
            "stage": "extract_partner_identity",
            "status": "complete",
            "partner_id": partner_id,
        })
        
        # Stage 5: IR.21 lookup — protocol-specific identity (SS7 GT, Diameter realm, GTP IMSI/IP)
        partner_record = self._lookup_partner(
            protocol=protocol,
            calling_gt=calling_gt,
            origin_realm=origin_realm,
            origin_host=origin_host,
            imsi=imsi,
            source_gateway=source_gateway or source,
            partner_id=partner_id,
        )
        
        partner_found = partner_record is not None
        checks.append({
            "check": "partner_ir21_lookup",
            "partner_id": partner_id,
            "origin_realm": origin_realm,
            "found": partner_found,
            "operator_name": partner_record.operator_name if partner_record else None,
        })
        
        stages.append({
            "stage": "ir21_lookup",
            "status": "found" if partner_found else "not_found",
            "partner_id": partner_id,
        })
        
        if not partner_found:
            # BLOCK: Unknown partner
            processing_time = (time.perf_counter() - start_time) * 1000
            return self._make_decision(
                decision_type=DecisionType.BLOCK,
                protocol=protocol,
                procedure=procedure,
                direction=direction,
                origin_realm=origin_realm,
                origin_host=origin_host,
                imsi_masked=imsi_masked,
                source=source,
                destination=destination,
                validation=ValidationResult(
                    authorized_procedure=True,
                    partner_found_in_ir21=False,
                    parameters_consistent=False,
                    checks=checks,
                ),
                reason=f"Partner not found in IR.21 (gt={calling_gt or '-'}, realm={origin_realm or '-'}, partner={partner_id})",
                stages=stages,
                processing_time=processing_time,
                rule_match=rule_match,
            )
        
        # Stage 6: Parameter + CAT2 rule IR.21 contextual checks
        params_consistent, mismatches, ir_evidence = self._check_parameters(
            message, partner_record, matched_rules=matched_rules
        )
        if matched_rules:
            ir_evidence.section = ir_evidence.section or matched_rules[0].gsma_reference
        checks.append({
            "check": "parameters_consistent",
            "consistent": params_consistent,
            "mismatches": mismatches,
            "ir21_checks": sorted({c for r in matched_rules for c in r.ir21_checks}),
        })
        
        stages.append({
            "stage": "parameter_check",
            "status": "pass" if params_consistent else "fail",
            "mismatches": mismatches,
        })
        
        processing_time = (time.perf_counter() - start_time) * 1000
        
        if not params_consistent:
            # BLOCK: Parameter mismatch
            return self._make_decision(
                decision_type=DecisionType.BLOCK,
                protocol=protocol,
                procedure=procedure,
                direction=direction,
                origin_realm=origin_realm,
                origin_host=origin_host,
                imsi_masked=imsi_masked,
                source=source,
                destination=destination,
                validation=ValidationResult(
                    authorized_procedure=True,
                    partner_found_in_ir21=True,
                    parameters_consistent=False,
                    checks=checks,
                ),
                ir_evidence=ir_evidence,
                reason=f"Parameter mismatch: {', '.join(mismatches)}",
                stages=stages,
                processing_time=processing_time,
                rule_match=rule_match,
            )
        
        # ALLOW: All checks passed
        return self._make_decision(
            decision_type=DecisionType.ALLOW,
            protocol=protocol,
            procedure=procedure,
            direction=direction,
            origin_realm=origin_realm,
            origin_host=origin_host,
            imsi_masked=imsi_masked,
            source=source,
            destination=destination,
            validation=ValidationResult(
                authorized_procedure=True,
                partner_found_in_ir21=True,
                parameters_consistent=True,
                checks=checks,
            ),
            ir_evidence=ir_evidence,
            reason=f"All CAT2 IR.21 checks passed for {partner_record.operator_name} ({partner_record.document_id or partner_record.partner_id})",
            stages=stages,
            processing_time=processing_time,
            rule_match=rule_match,
        )
    
    def _procedure_matches(self, procedure: str, authorized: list[str]) -> bool:
        """Check if procedure matches any authorized procedure."""
        proc_lower = procedure.lower().replace("-", "").replace("_", "")
        for auth in authorized:
            auth_lower = auth.lower().replace("-", "").replace("_", "")
            if proc_lower == auth_lower or proc_lower in auth_lower or auth_lower in proc_lower:
                return True
        return False
    
    def _extract_partner_identity(self, message: dict[str, Any], protocol: str) -> str:
        """Extract partner identity based on protocol."""
        if protocol == "Diameter":
            return message.get("origin_realm", "") or message.get("origin_host", "")
        elif protocol == "GTP-C":
            imsi = message.get("imsi", "")
            if imsi and len(imsi) >= 5:
                return f"PLMN-{imsi[:3]}-{imsi[3:5]}"
            return message.get("source_gateway", "")
        elif protocol in ("MAP", "SCCP", "CAP"):
            return message.get("calling_gt", "") or message.get("global_title", "")
        return ""
    
    def _match_cat2_rules(self, protocol: str, procedure: str, direction: str):
        """Match enabled CAT2 IR.21 rules for this protocol/procedure/direction."""
        matches = []
        for rule in self.rules:
            if rule.protocol.upper() != protocol.upper() and not (
                protocol == "MAP" and rule.protocol.upper() == "SCCP"
            ):
                # MAP over SCCP can still match SCCP GT rules when procedure is UDT-like
                if not (protocol in ("MAP", "SCCP") and rule.protocol.upper() in ("MAP", "SCCP")):
                    continue
            if rule.direction.upper() != direction.upper():
                continue
            if self._procedure_matches(procedure, [rule.procedure]):
                matches.append(rule)
        return matches
    
    @staticmethod
    def _rule_to_match(rule, protocol: str, calling_gt: str, origin_realm: str) -> RuleMatch:
        return RuleMatch(
            rule_id=rule.rule_id,
            sid=0,
            name=rule.name,
            category="CAT2",
            severity=rule.severity,
            rule_text=rule.validation_logic,
            matched_fields={
                "protocol": protocol,
                "procedure": rule.procedure,
                "ir21_checks": rule.ir21_checks,
                "calling_gt": calling_gt,
                "origin_realm": origin_realm,
            },
            reference=rule.gsma_reference,
        )
    
    def _lookup_partner(
        self,
        protocol: str,
        calling_gt: str,
        origin_realm: str,
        origin_host: str,
        imsi: str,
        source_gateway: str,
        partner_id: str,
    ) -> PartnerRecord | None:
        """Resolve IR.21 partner using the identity that protocol carries."""
        record = None
        if protocol in ("MAP", "SCCP", "CAP") and calling_gt:
            record = self.ir21_store.lookup_by_gt(calling_gt)
        if not record and origin_realm:
            record = self.ir21_store.lookup_by_realm(origin_realm)
        if not record and origin_host:
            record = self.ir21_store.lookup_by_host(origin_host)
        if not record and imsi:
            record = self.ir21_store.lookup_by_imsi(imsi)
        if not record and partner_id:
            record = self.ir21_store.lookup(partner_id)
            if not record and protocol in ("MAP", "SCCP", "CAP"):
                record = self.ir21_store.lookup_by_gt(partner_id)
        return record
    
    def _check_parameters(
        self,
        message: dict[str, Any],
        partner: PartnerRecord,
        matched_rules: list | None = None,
    ) -> tuple[bool, list[str], IR21Evidence]:
        """Check message parameters against IR.21 partner record and CAT2 rule checks."""
        mismatches: list[str] = []
        observed: dict[str, Any] = {}
        expected: dict[str, Any] = {}
        matched_fields: list[str] = []
        checks_to_run: list[str] = []
        for rule in matched_rules or []:
            checks_to_run.extend(rule.ir21_checks)
        # Always apply core consistency checks when the field is present
        checks_to_run.extend(["agreement_status", "origin_realm", "imsi_prefix", "apn_list", "serving_network"])
        # Deduplicate while preserving order
        seen: set[str] = set()
        ordered_checks: list[str] = []
        for c in checks_to_run:
            if c not in seen:
                seen.add(c)
                ordered_checks.append(c)
        
        calling_gt = str(message.get("calling_gt") or message.get("global_title") or "")
        origin_realm = str(message.get("origin_realm", ""))
        origin_host = str(message.get("origin_host", ""))
        imsi = str(message.get("imsi") or message.get("subscriber_id", ""))
        serving = str(message.get("serving_network", ""))
        apn = str(message.get("apn", ""))
        procedure = str(message.get("procedure", ""))
        cap_version = str(message.get("cap_version", ""))
        map_version = str(message.get("map_version", ""))
        source_ip = str(message.get("source_gateway") or message.get("source") or "")
        
        def _ok(field: str, obs: Any, exp: Any) -> None:
            observed[field] = obs
            expected[field] = exp
            matched_fields.append(field)
        
        def _fail(field: str, obs: Any, exp: Any) -> None:
            observed[field] = obs
            expected[field] = exp
            mismatches.append(field)
        
        for check in ordered_checks:
            if check in ("partner_gt", "sccp_gt_range"):
                prefixes = partner.gt_prefixes
                if calling_gt and prefixes:
                    gt_clean = "".join(c for c in calling_gt if c.isdigit())
                    if any(gt_clean.startswith("".join(c for c in p if c.isdigit())) for p in prefixes):
                        _ok("partner_gt", calling_gt, prefixes)
                    else:
                        _fail("partner_gt", calling_gt, prefixes)
            elif check == "smsc_gt_list":
                if calling_gt and partner.smsc_gts:
                    gt_clean = "".join(c for c in calling_gt if c.isdigit())
                    if any(gt_clean.startswith("".join(c for c in p if c.isdigit())) for p in partner.smsc_gts):
                        _ok("smsc_gt", calling_gt, partner.smsc_gts)
                    else:
                        _fail("smsc_gt", calling_gt, partner.smsc_gts)
            elif check == "scp_gt_list":
                if calling_gt and partner.scp_gts:
                    gt_clean = "".join(c for c in calling_gt if c.isdigit())
                    if any(gt_clean.startswith("".join(c for c in p if c.isdigit())) for p in partner.scp_gts):
                        _ok("scp_gt", calling_gt, partner.scp_gts)
                    else:
                        _fail("scp_gt", calling_gt, partner.scp_gts)
            elif check in ("mcc_mnc", "partner_mcc_mnc", "imsi_prefix"):
                if imsi and len(imsi) >= 5 and partner.mcc and partner.mnc:
                    imsi_plmn = f"{imsi[:3]}-{imsi[3:5]}"
                    expected_plmn = f"{partner.mcc}-{partner.mnc}"
                    # 3-digit MNC (e.g. Maxis 502-12)
                    if partner.mnc and len(partner.mnc) == 2 and imsi[:5] == f"{partner.mcc}{partner.mnc}":
                        _ok("imsi_mccmnc", imsi_plmn, expected_plmn)
                    elif partner.mnc and len(partner.mnc) == 2 and len(imsi) >= 6 and imsi[:6] == f"{partner.mcc}0{partner.mnc}":
                        _ok("imsi_mccmnc", f"{imsi[:3]}-{imsi[3:6]}", expected_plmn)
                    elif imsi[:3] == partner.mcc and imsi[3:3+len(partner.mnc)] == partner.mnc:
                        _ok("imsi_mccmnc", imsi_plmn, expected_plmn)
                    else:
                        _fail("imsi_mcc_mnc", imsi_plmn, expected_plmn)
            elif check == "agreement_status":
                if partner.agreement_status != "ACTIVE":
                    _fail("agreement_status", partner.agreement_status, "ACTIVE")
                else:
                    _ok("agreement_status", partner.agreement_status, "ACTIVE")
            elif check == "authorized_procedures":
                if partner.authorized_procedures and procedure:
                    if not self._procedure_matches(procedure, partner.authorized_procedures):
                        _fail("authorized_procedures", procedure, partner.authorized_procedures)
                    else:
                        _ok("authorized_procedures", procedure, partner.authorized_procedures)
            elif check == "voice_roaming_enabled":
                if partner.voice_roaming is False:
                    _fail("voice_roaming", False, True)
                else:
                    _ok("voice_roaming", partner.voice_roaming, True)
            elif check in ("sms_interworking",):
                if partner.sms_roaming is False:
                    _fail("sms_roaming", False, True)
                else:
                    _ok("sms_roaming", partner.sms_roaming, True)
            elif check == "origin_realm":
                if origin_realm and partner.origin_realm:
                    if origin_realm.lower() == partner.origin_realm.lower() or origin_realm.lower().endswith("." + partner.origin_realm.lower()):
                        _ok("origin_realm", origin_realm, partner.origin_realm)
                    else:
                        _fail("origin_realm", origin_realm, partner.origin_realm)
            elif check in ("origin_host", "diameter_peers", "dea_fqdn"):
                hosts = partner.origin_hosts + partner.diameter_peers + partner.dea_fqdns
                if origin_host and hosts:
                    host_l = origin_host.lower()
                    if any(host_l == h.lower() or host_l.endswith("." + h.lower()) for h in hosts if h):
                        _ok("origin_host", origin_host, hosts)
                    else:
                        _fail("origin_host", origin_host, hosts)
            elif check == "authorized_applications":
                if partner.diameter_applications:
                    _ok("diameter_applications", partner.diameter_applications, partner.diameter_applications)
            elif check == "lte_roaming_enabled":
                if partner.lte_roaming is False:
                    _fail("lte_roaming", False, True)
                else:
                    _ok("lte_roaming", partner.lte_roaming, True)
            elif check in ("apn_list",):
                if apn and partner.expected_apn:
                    if apn not in partner.expected_apn:
                        _fail("apn", apn, partner.expected_apn)
                    else:
                        _ok("apn", apn, partner.expected_apn)
            elif check == "data_roaming_enabled":
                if partner.data_roaming is False:
                    _fail("data_roaming", False, True)
                else:
                    _ok("data_roaming", partner.data_roaming, True)
            elif check in ("serving_network", "partner_plmn_list"):
                if serving and partner.serving_network_mcc_mnc:
                    serving_norm = serving.replace(" ", "")
                    expected_sn = partner.serving_network_mcc_mnc
                    alt = f"{partner.mcc}{partner.mnc}"
                    if serving_norm in (expected_sn, alt, expected_sn.replace("-", "")):
                        _ok("serving_network", serving, expected_sn)
                    else:
                        _fail("serving_network_mcc_mnc", serving, expected_sn)
            elif check == "map_version":
                if map_version and partner.map_versions:
                    if map_version not in partner.map_versions and not any(map_version.lower() in v.lower() for v in partner.map_versions):
                        _fail("map_version", map_version, partner.map_versions)
                    else:
                        _ok("map_version", map_version, partner.map_versions)
            elif check == "cap_version":
                if cap_version and partner.cap_versions:
                    if cap_version not in partner.cap_versions and not any(cap_version.lower() in v.lower() for v in partner.cap_versions):
                        _fail("cap_version", cap_version, partner.cap_versions)
                    else:
                        _ok("cap_version", cap_version, partner.cap_versions)
            elif check in ("gtp_ip_range",):
                if source_ip and partner.ip_ranges:
                    if self._ip_in_ranges(source_ip, partner.ip_ranges):
                        _ok("gtp_ip_range", source_ip, partner.ip_ranges)
                    else:
                        _fail("gtp_ip_range", source_ip, partner.ip_ranges)
            elif check == "gtp_version":
                gv = str(message.get("gtp_version", ""))
                if gv and partner.gtp_version and gv.lower() not in partner.gtp_version.lower():
                    _fail("gtp_version", gv, partner.gtp_version)
                elif gv and partner.gtp_version:
                    _ok("gtp_version", gv, partner.gtp_version)
        
        ir_evidence = IR21Evidence(
            document=partner.document_id or "IR.21",
            section=partner.document_section,
            partner_id=partner.partner_id,
            matched_fields=matched_fields,
            expected_values=expected,
            observed_values=observed,
            mismatches=mismatches,
        )
        
        return len(mismatches) == 0, mismatches, ir_evidence
    
    @staticmethod
    def _ip_in_ranges(ip: str, ranges: list[str]) -> bool:
        """Return True if ip is inside any CIDR (best-effort; hostnames skip)."""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        for r in ranges:
            try:
                if addr in ipaddress.ip_network(r, strict=False):
                    return True
            except Exception:
                if ip == r:
                    return True
        return False
    
    def _make_decision(
        self,
        decision_type: DecisionType,
        protocol: str,
        procedure: str,
        direction: str,
        origin_realm: str,
        origin_host: str,
        imsi_masked: str,
        source: str,
        destination: str,
        validation: ValidationResult,
        reason: str,
        stages: list[dict[str, Any]],
        processing_time: float,
        ir_evidence: IR21Evidence | None = None,
        rule_match: RuleMatch | None = None,
    ) -> Decision:
        """Create a CAT2 decision."""
        return Decision(
            decision=decision_type,
            category=Category.CAT2,
            confidence=1.0,
            protocol=Protocol.from_string(protocol),
            procedure=procedure,
            source=source,
            destination=destination,
            origin_realm=origin_realm,
            origin_host=origin_host,
            subscriber_id_masked=imsi_masked,
            validation=validation,
            ir_evidence=ir_evidence,
            rule_match=rule_match,
            detection_rule=rule_match.rule_id if rule_match else "",
            attack_pattern=rule_match.attack_pattern if rule_match else "",
            enforcement="BLOCK" if decision_type == DecisionType.BLOCK else "PASS",
            enforcement_confirmed=not self.dry_run,
            dry_run=self.dry_run,
            reason=reason,
            explanation=f"CAT2 {direction} {protocol} IR.21 contextual validation: {reason}",
            processing_latency_ms=processing_time,
            stages=stages,
        )
    
    def _mask_imsi(self, imsi: str) -> str:
        """Mask IMSI for privacy."""
        if not imsi or len(imsi) < 10:
            return "***"
        return imsi[:5] + "*" * (len(imsi) - 7) + imsi[-2:]
