"""
CAT1 Detection Engine — Immediate Rule-Based Blocking

CAT1 messages are prohibited operations that should never appear on 
the interconnect. Block immediately without contextual lookup.

Examples:
- Unauthorized ATI (AnyTimeInterrogation) from external GT
- Prohibited MAP opcodes on international roaming interface
- Category-1 Diameter commands from untrusted realms
"""

from __future__ import annotations

import re
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
)


@dataclass
class CAT1Rule:
    """A CAT1 detection rule."""
    rule_id: str
    sid: int
    name: str
    protocol: str
    opcode: int | None = None
    opcodes: list[int] = field(default_factory=list)
    attack_pattern: str = ""
    detection_rule: str = ""
    authorized_gt_list: list[str] = field(default_factory=list)
    authorized_realms: list[str] = field(default_factory=list)
    action: str = "BLOCK"  # BLOCK or ALERT
    severity: str = "high"
    reference: str = ""
    rule_text: str = ""
    enabled: bool = True
    
    def matches_opcode(self, opcode: int | None) -> bool:
        """Check if opcode matches this rule."""
        if opcode is None:
            return False
        if self.opcode is not None and opcode == self.opcode:
            return True
        if self.opcodes and opcode in self.opcodes:
            return True
        return False


# Load predefined 3G/4G CAT1 rules
def _load_default_cat1_rules() -> list[CAT1Rule]:
    """Load default CAT1 rules from 3G/4G ruleset."""
    from app.ids.rules_3g4g import get_all_cat1_rules, CAT1Rule as Rule3G4G
    
    rules = []
    for r in get_all_cat1_rules():
        opcode = r.opcode or r.command_code or r.message_type
        rules.append(CAT1Rule(
            rule_id=r.rule_id,
            sid=r.sid,
            name=r.name,
            protocol=r.protocol,
            opcode=opcode,
            attack_pattern=r.attack_pattern,
            detection_rule=r.rule_id,
            action=r.action,
            severity=r.severity,
            reference=r.gsma_reference,
            rule_text=r.rule_text,
            enabled=r.enabled,
        ))
    return rules


DEFAULT_CAT1_RULES: list[CAT1Rule] = _load_default_cat1_rules()


class CAT1Engine:
    """
    CAT1 Immediate Rule-Based Blocking Engine.
    
    Fast-path detection with IR.21 contextual validation:
    1. Parse message fields
    2. Check GT/Realm against IR.21 authorized partners
    3. Match opcode against CAT1 rules
    4. Block immediately if matched
    """
    
    def __init__(
        self,
        authorized_gt_list: list[str] | None = None,
        authorized_realms: list[str] | None = None,
        custom_rules: list[CAT1Rule] | None = None,
        dry_run: bool = False,
        use_ir21: bool = True,
    ):
        self.authorized_gt_list = set(authorized_gt_list or [])
        self.authorized_realms = set(authorized_realms or [])
        self.rules = list(custom_rules) if custom_rules else list(DEFAULT_CAT1_RULES)
        self.dry_run = dry_run
        self.use_ir21 = use_ir21
        
        # Load IR.21 authorized sources
        if use_ir21:
            self._load_ir21_authorized_sources()
        
        # Index rules by protocol and opcode for fast lookup
        self._rule_index: dict[str, dict[int, list[CAT1Rule]]] = {}
        self._rebuild_index()
    
    def _load_ir21_authorized_sources(self) -> None:
        """Load authorized GTs and realms from IR.21 partners."""
        try:
            from app.ids.rules_3g4g import get_all_ir21_partners
            
            for partner in get_all_ir21_partners():
                # Add GT prefixes
                for gt in partner.gt_prefixes:
                    self.authorized_gt_list.add(gt)
                # Add SMSC GTs
                for smsc in partner.smsc_gts:
                    self.authorized_gt_list.add(smsc)
                # Add HLR GTs
                for hlr in partner.hlr_gts:
                    self.authorized_gt_list.add(hlr)
                # Add Diameter realms
                if partner.origin_realm:
                    self.authorized_realms.add(partner.origin_realm)
                # Add origin hosts
                for host in partner.origin_hosts:
                    self.authorized_realms.add(host)
            
            print(f"[CAT1] Loaded IR.21: {len(self.authorized_gt_list)} GTs, {len(self.authorized_realms)} realms")
        except Exception as e:
            print(f"[CAT1] Failed to load IR.21: {e}")
    
    def _rebuild_index(self) -> None:
        """Build opcode lookup index."""
        self._rule_index = {}
        for rule in self.rules:
            if not rule.enabled:
                continue
            proto = rule.protocol.upper()
            if proto not in self._rule_index:
                self._rule_index[proto] = {}
            
            opcodes = []
            if rule.opcode is not None:
                opcodes.append(rule.opcode)
            opcodes.extend(rule.opcodes)
            
            for opc in opcodes:
                if opc not in self._rule_index[proto]:
                    self._rule_index[proto][opc] = []
                self._rule_index[proto][opc].append(rule)
    
    def add_rule(self, rule: CAT1Rule) -> None:
        """Add a CAT1 rule."""
        self.rules.append(rule)
        self._rebuild_index()
    
    def set_authorized_gts(self, gts: list[str]) -> None:
        """Set authorized Global Title list."""
        self.authorized_gt_list = set(gts)
    
    def set_authorized_realms(self, realms: list[str]) -> None:
        """Set authorized Diameter realms."""
        self.authorized_realms = set(realms)
    
    def is_gt_authorized(self, gt: str) -> bool:
        """Check if Global Title is in authorized list."""
        if not self.authorized_gt_list:
            return False  # No whitelist = all external are unauthorized
        gt_clean = re.sub(r'[^\d]', '', gt)
        if not gt_clean:
            return False
        for auth_gt in self.authorized_gt_list:
            auth_clean = re.sub(r'[^\d]', '', auth_gt)
            if not auth_clean:
                continue
            if gt_clean.startswith(auth_clean) or auth_clean.startswith(gt_clean):
                return True
        return False
    
    def is_realm_authorized(self, realm: str) -> bool:
        """Check if Diameter realm is authorized."""
        if not self.authorized_realms:
            return False
        realm_lower = realm.lower()
        return any(realm_lower == r.lower() or realm_lower.endswith('.' + r.lower()) 
                   for r in self.authorized_realms)
    
    def _check_gt_ir21(self, gt: str) -> tuple[bool, dict | None]:
        """Check GT against IR.21 partners."""
        try:
            from app.ids.rules_3g4g import get_partner_by_gt
            partner = get_partner_by_gt(gt)
            if partner:
                return True, {
                    "partner_id": partner.partner_id,
                    "operator_name": partner.operator_name,
                    "country": partner.country,
                    "mcc": partner.mcc,
                    "mnc": partner.mnc,
                    "gt_prefixes": partner.gt_prefixes,
                }
        except Exception:
            pass
        # Fallback to static list
        return self.is_gt_authorized(gt), None
    
    def _check_realm_ir21(self, realm: str) -> tuple[bool, dict | None]:
        """Check Diameter realm against IR.21 partners."""
        try:
            from app.ids.rules_3g4g import get_partner_by_realm
            partner = get_partner_by_realm(realm)
            if partner:
                return True, {
                    "partner_id": partner.partner_id,
                    "operator_name": partner.operator_name,
                    "country": partner.country,
                    "mcc": partner.mcc,
                    "mnc": partner.mnc,
                    "origin_realm": partner.origin_realm,
                    "origin_hosts": partner.origin_hosts,
                }
        except Exception:
            pass
        # Fallback to static list
        return self.is_realm_authorized(realm), None
    
    def _check_gtp_ir21(self, source_gw: str, imsi: str) -> tuple[bool, dict | None]:
        """Check GTP-C source against IR.21 partners."""
        try:
            from app.ids.rules_3g4g import get_partner_by_mccmnc
            # Use IMSI MCC/MNC to identify partner
            if imsi and len(imsi) >= 5:
                mcc = imsi[:3]
                mnc = imsi[3:5]
                partner = get_partner_by_mccmnc(mcc, mnc)
                if partner:
                    return True, {
                        "partner_id": partner.partner_id,
                        "operator_name": partner.operator_name,
                        "country": partner.country,
                        "mcc": partner.mcc,
                        "mnc": partner.mnc,
                        "pgw_addresses": partner.pgw_addresses,
                        "sgw_addresses": partner.sgw_addresses,
                    }
        except Exception:
            pass
        return False, None
    
    def inspect(self, message: dict[str, Any]) -> Decision:
        """
        Inspect a signaling message for CAT1 violations.
        
        Args:
            message: Parsed signaling message with fields:
                - protocol: MAP, Diameter, GTP-C, SCCP
                - opcode: MAP opcode or Diameter command code
                - calling_gt: Source Global Title
                - origin_realm: Diameter Origin-Realm
                - origin_host: Diameter Origin-Host
                - source: Source address
                - destination: Destination address
                - imsi: Subscriber IMSI (will be masked)
                - raw_payload: Optional raw message bytes
        
        Returns:
            Decision with ALLOW or BLOCK
        """
        start_time = time.perf_counter()
        stages: list[dict[str, Any]] = []
        
        # Stage 1: Parse message fields
        stages.append({
            "stage": "parse",
            "status": "complete",
            "duration_ms": 0,
        })
        
        protocol = str(message.get("protocol", "")).upper()
        opcode = message.get("opcode")
        if opcode is not None:
            try:
                opcode = int(opcode)
            except (ValueError, TypeError):
                opcode = None
        
        calling_gt = str(message.get("calling_gt") or message.get("global_title") or "")
        origin_realm = str(message.get("origin_realm", ""))
        origin_host = str(message.get("origin_host", ""))
        source = str(message.get("source", ""))
        destination = str(message.get("destination", ""))
        procedure = str(message.get("procedure", ""))
        imsi = str(message.get("imsi") or message.get("subscriber_id", ""))
        
        # Mask IMSI for privacy
        imsi_masked = self._mask_imsi(imsi) if imsi else ""
        
        # Stage 2: Check authorization against IR.21 partners
        gt_authorized = True
        realm_authorized = True
        ir21_partner = None
        ir21_evidence = None
        
        if protocol in ("MAP", "SCCP") and calling_gt:
            gt_authorized, ir21_partner = self._check_gt_ir21(calling_gt)
            stages.append({
                "stage": "gt_authorization",
                "status": "authorized" if gt_authorized else "unauthorized",
                "global_title": calling_gt,
                "ir21_partner": ir21_partner.get("operator_name") if ir21_partner else None,
                "duration_ms": 0,
            })
            if ir21_partner:
                ir21_evidence = IR21Evidence(
                    document="IR.21",
                    partner_id=ir21_partner.get("partner_id", ""),
                    matched_fields=["gt_prefix"],
                    expected_values={"authorized_gts": ir21_partner.get("gt_prefixes", [])},
                    observed_values={"calling_gt": calling_gt},
                )
        
        if protocol == "DIAMETER" and origin_realm:
            realm_authorized, ir21_partner = self._check_realm_ir21(origin_realm)
            stages.append({
                "stage": "realm_authorization", 
                "status": "authorized" if realm_authorized else "unauthorized",
                "origin_realm": origin_realm,
                "ir21_partner": ir21_partner.get("operator_name") if ir21_partner else None,
                "duration_ms": 0,
            })
            if ir21_partner:
                ir21_evidence = IR21Evidence(
                    document="IR.21",
                    partner_id=ir21_partner.get("partner_id", ""),
                    matched_fields=["origin_realm"],
                    expected_values={"authorized_realm": ir21_partner.get("origin_realm", "")},
                    observed_values={"origin_realm": origin_realm},
                )
        
        # Check GTP-C source
        if protocol == "GTP-C" or protocol == "GTP_C":
            source_gw = str(message.get("source_gateway") or source or "")
            gtp_authorized, ir21_partner = self._check_gtp_ir21(source_gw, message.get("imsi", ""))
            stages.append({
                "stage": "gtp_authorization",
                "status": "authorized" if gtp_authorized else "unauthorized",
                "source_gateway": source_gw,
                "ir21_partner": ir21_partner.get("operator_name") if ir21_partner else None,
                "duration_ms": 0,
            })
            if not gtp_authorized:
                gt_authorized = False  # Use gt_authorized for unified check
        
        # Stage 3: Rule matching
        matched_rule: CAT1Rule | None = None
        
        if opcode is not None and protocol in self._rule_index:
            proto_rules = self._rule_index[protocol]
            if opcode in proto_rules:
                for rule in proto_rules[opcode]:
                    # CAT1 triggers when source is NOT authorized
                    if protocol in ("MAP", "SCCP") and not gt_authorized:
                        matched_rule = rule
                        break
                    elif protocol == "DIAMETER" and not realm_authorized:
                        matched_rule = rule
                        break
                    elif protocol in ("GTP-C", "GTP_C") and not gt_authorized:
                        matched_rule = rule
                        break
        
        stages.append({
            "stage": "rule_matching",
            "status": "matched" if matched_rule else "no_match",
            "rule_id": matched_rule.rule_id if matched_rule else None,
            "opcode": opcode,
            "duration_ms": 0,
        })
        
        # Stage 4: Decision
        processing_time = (time.perf_counter() - start_time) * 1000
        
        if matched_rule:
            # CAT1 BLOCK
            decision = Decision(
                decision=DecisionType.BLOCK,
                category=Category.CAT1,
                confidence=1.0,
                protocol=Protocol.from_string(protocol),
                procedure=procedure or self._opcode_to_procedure(protocol, opcode),
                opcode=opcode,
                source=source,
                destination=destination,
                global_title=calling_gt,
                origin_realm=origin_realm,
                origin_host=origin_host,
                subscriber_id_masked=imsi_masked,
                attack_pattern=matched_rule.attack_pattern,
                detection_rule=matched_rule.detection_rule,
                rule_sid=matched_rule.sid,
                rule_match=RuleMatch(
                    rule_id=matched_rule.rule_id,
                    sid=matched_rule.sid,
                    revision=1,
                    name=matched_rule.name,
                    attack_pattern=matched_rule.attack_pattern,
                    category="CAT1",
                    severity=matched_rule.severity,
                    rule_text=matched_rule.rule_text,
                    matched_fields={
                        "opcode": opcode,
                        "calling_gt": calling_gt,
                        "origin_realm": origin_realm,
                        "gt_authorized": gt_authorized,
                        "realm_authorized": realm_authorized,
                        "ir21_partner": ir21_partner.get("operator_name") if ir21_partner else None,
                    },
                    reference=matched_rule.reference,
                ),
                ir_evidence=ir21_evidence,
                enforcement="DROP" if matched_rule.action == "BLOCK" else "ALERT",
                enforcement_confirmed=not self.dry_run,
                dry_run=self.dry_run,
                reason=f"Unauthorized {self._opcode_to_procedure(protocol, opcode)} from external source",
                explanation=f"CAT1 violation: {matched_rule.name}. Source GT/Realm not in IR.21 authorized partners list.",
                processing_latency_ms=processing_time,
                stages=stages,
            )
        else:
            # CAT1 ALLOW (no rule match or authorized source)
            decision = Decision(
                decision=DecisionType.ALLOW,
                category=Category.CAT1,
                confidence=1.0,
                protocol=Protocol.from_string(protocol),
                procedure=procedure or self._opcode_to_procedure(protocol, opcode),
                opcode=opcode,
                source=source,
                destination=destination,
                global_title=calling_gt,
                origin_realm=origin_realm,
                origin_host=origin_host,
                subscriber_id_masked=imsi_masked,
                ir_evidence=ir21_evidence,
                enforcement="PASS",
                enforcement_confirmed=True,
                dry_run=self.dry_run,
                reason=f"Source authorized via IR.21 partner: {ir21_partner.get('operator_name', 'N/A') if ir21_partner else 'No rule match'}",
                processing_latency_ms=processing_time,
                stages=stages,
            )
        
        return decision
    
    def _mask_imsi(self, imsi: str) -> str:
        """Mask IMSI for privacy (show first 5 and last 2 digits)."""
        if not imsi or len(imsi) < 10:
            return "***"
        return imsi[:5] + "*" * (len(imsi) - 7) + imsi[-2:]
    
    def _opcode_to_procedure(self, protocol: str, opcode: int | None) -> str:
        """Convert opcode to procedure name."""
        if opcode is None:
            return ""
        
        map_opcodes = {
            2: "UpdateLocation",
            3: "CancelLocation",
            4: "ProvideRoamingNumber",
            7: "InsertSubscriberData",
            8: "DeleteSubscriberData",
            9: "SendParameters",
            22: "SendAuthenticationInfo",
            45: "SendRoutingInfoForSM",
            46: "MT-ForwardSM",
            47: "ReportSMDeliveryStatus",
            56: "SendRoutingInfo",
            58: "SendIMSI",
            66: "ReadyForSM",
            70: "ProvideSubscriberInfo",
            71: "AnyTimeInterrogation",
            72: "AnyTimeSubscriptionInterrogation",
            83: "ProvideSubscriberLocation",
        }
        
        diameter_commands = {
            265: "AA-Request",
            268: "Diameter-EAP-Request",
            271: "Accounting-Request",
            274: "Abort-Session-Request",
            275: "Session-Termination-Request",
            300: "User-Authorization-Request",
            301: "Server-Assignment-Request",
            302: "Location-Info-Request",
            303: "Multimedia-Auth-Request",
            304: "Registration-Termination-Request",
            305: "Push-Profile-Request",
            316: "Update-Location-Request",
            317: "Cancel-Location-Request",
            318: "Authentication-Information-Request",
            319: "Insert-Subscriber-Data-Request",
            320: "Delete-Subscriber-Data-Request",
            321: "Purge-UE-Request",
            322: "Reset-Request",
            323: "Notify-Request",
        }
        
        if protocol == "MAP":
            return map_opcodes.get(opcode, f"MAP-{opcode}")
        elif protocol == "DIAMETER":
            return diameter_commands.get(opcode, f"Diameter-{opcode}")
        
        return f"{protocol}-{opcode}"
