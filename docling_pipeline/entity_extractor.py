"""Domain NER for telecom / IR.21 documents + relationship extraction."""

from __future__ import annotations

import re
from typing import List, Optional

import config
from shared.ir21_schema import IR21Profile, RelationRecord
from shared.schema import EntityRecord

_PATTERNS: dict[str, re.Pattern] = {
    "IP_ADDRESS": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?\b"
    ),
    "PORT": re.compile(r"\b(?:port\s*[:=]?\s*)(\d{2,5})\b", re.IGNORECASE),
    "HOSTNAME": re.compile(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\b"
    ),
    "URL": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    "DATE": re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b"),
    "TADIG": re.compile(r"\b(?:TADIG(?:\s*code)?\s*[:=]?\s*)?([A-Z]{5})\b"),
    "MCC": re.compile(r"\bMCC\s*[:=]?\s*(\d{3})\b|\bmcc(\d{3})\b", re.I),
    "MNC": re.compile(r"\bMNC\s*[:=]?\s*(\d{2,3})\b|\bmnc(\d{2,3})\b", re.I),
    "IMSI_RANGE": re.compile(r"\b(?:IMSI)\s*[:=]?\s*(\d{6,15}(?:\s*[-–]\s*\d{6,15})?)\b", re.I),
    "MSISDN_RANGE": re.compile(
        r"\b(?:MSISDN|E\.?164)\s*[:=]?\s*(\+?\d{6,15}(?:\s*[-–]\s*\d{0,15})?)\b", re.I
    ),
    "GT": re.compile(r"\b(?:GT|Global\s*Title)\s*[:=]?\s*([\d\s]{6,20})\b", re.I),
    "REALM": re.compile(r"\b([a-z0-9.-]+\.3gppnetwork\.org)\b", re.I),
    "SECTION_ID": re.compile(r"\bSection\s*ID\s*[:=]?\s*(\d{1,2})\b", re.I),
    "NODE_TYPE": re.compile(
        r"\b(HLR|HSS|VLR|MSC|GMSC|SGSN|GGSN|MME|PGW|SGW|PCRF|DEA|DRA|BSC|RNC|MMSC|SMSC)\b",
        re.I,
    ),
    "PROTOCOL": re.compile(r"\b(Diameter|MAP|CAP|CAMEL|GTP|GTPv2|S6a|S8|Gy|Gx|SCCP|ISUP|SIP)\b", re.I),
    "QOS_PROFILE": re.compile(r"\b(qos\d+|QoS\s*Profile\s*\w+)\b", re.I),
    "IDENTIFIER": re.compile(r"\b[A-Z]{2,}[-_]\d+\b"),
}


def extract_entities(
    text: str,
    document_id: str,
    section_id: Optional[str] = None,
    table_id: Optional[str] = None,
    row_id: Optional[str] = None,
    page: Optional[int] = None,
) -> List[EntityRecord]:
    """Extract domain entities from text (IR.21-aware)."""
    enabled = set(config.ENTITY_TYPES)
    # Always allow IR.21 domain types even if not listed in env
    enabled |= {
        "IP_ADDRESS", "PORT", "HOSTNAME", "URL", "DATE", "TADIG", "MCC", "MNC",
        "IMSI_RANGE", "MSISDN_RANGE", "GT", "REALM", "SECTION_ID", "NODE_TYPE",
        "PROTOCOL", "QOS_PROFILE", "IDENTIFIER",
    }
    found: List[EntityRecord] = []
    seen: set[tuple[str, str]] = set()

    for etype, pattern in _PATTERNS.items():
        if etype not in enabled:
            continue
        for match in pattern.finditer(text or ""):
            groups = [g for g in match.groups() if g]
            value = groups[0] if groups else match.group(0)
            value = value.strip()
            if not value:
                continue
            if etype == "TADIG" and value.upper() in {"RAEX", "GSMA", "CCITT", "MSISDN"}:
                continue
            if etype == "HOSTNAME" and _PATTERNS["IP_ADDRESS"].fullmatch(value):
                continue
            if etype == "PORT":
                try:
                    p = int(value)
                    if p < 1 or p > 65535:
                        continue
                except ValueError:
                    continue
            key = (etype, value.lower())
            if key in seen:
                continue
            seen.add(key)
            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            found.append(
                EntityRecord(
                    entity=value,
                    type=etype,
                    document_id=document_id,
                    section_id=section_id,
                    table_id=table_id,
                    row_id=row_id,
                    page=page,
                    source_text=(text or "")[start:end].strip(),
                )
            )
    return found


def relations_from_profile(profile: IR21Profile) -> List[RelationRecord]:
    """Build entity relationships from a structured IR.21 profile."""
    rels: List[RelationRecord] = []
    op = profile.organisation_name or profile.tadig or profile.file_name
    op_type = "OPERATOR"

    def add(pred: str, obj: str, obj_type: str, section_id=None, page=None, src="") -> None:
        if not obj:
            return
        rels.append(
            RelationRecord(
                subject=op,
                subject_type=op_type,
                predicate=pred,
                object=obj,
                object_type=obj_type,
                document_id=profile.document_id,
                file_name=profile.file_name,
                section_id=section_id,
                page=page,
                source_text=src[:200],
            )
        )

    add("HAS_TADIG", profile.tadig, "TADIG")
    add("OPERATES_IN", profile.country, "COUNTRY")
    if profile.mcc and profile.mnc:
        plmn = f"{profile.mcc}-{profile.mnc}"
        add("HAS_PLMN", plmn, "PLMN")
        rels.append(
            RelationRecord(
                subject=plmn,
                subject_type="PLMN",
                predicate="HAS_MCC",
                object=profile.mcc,
                object_type="MCC",
                document_id=profile.document_id,
                file_name=profile.file_name,
            )
        )
        rels.append(
            RelationRecord(
                subject=plmn,
                subject_type="PLMN",
                predicate="HAS_MNC",
                object=profile.mnc,
                object_type="MNC",
                document_id=profile.document_id,
                file_name=profile.file_name,
            )
        )

    for ep in profile.endpoints:
        node = ep.fqdn or ep.node_id or ep.ip or ep.role
        if not node:
            continue
        role = (ep.role or ep.node_type or "ENDPOINT").upper()
        add("HAS_ENDPOINT", node, role, ep.section_id, ep.page)
        if ep.ip:
            rels.append(
                RelationRecord(
                    subject=node,
                    subject_type=role,
                    predicate="HAS_IP",
                    object=ep.ip,
                    object_type="IP_ADDRESS",
                    document_id=profile.document_id,
                    file_name=profile.file_name,
                    section_id=ep.section_id,
                    page=ep.page,
                )
            )
        if ep.ip_secondary:
            rels.append(
                RelationRecord(
                    subject=node,
                    subject_type=role,
                    predicate="HAS_IP",
                    object=ep.ip_secondary,
                    object_type="IP_ADDRESS",
                    document_id=profile.document_id,
                    file_name=profile.file_name,
                    section_id=ep.section_id,
                    page=ep.page,
                )
            )
        if ep.protocol:
            rels.append(
                RelationRecord(
                    subject=node,
                    subject_type=role,
                    predicate="USES_PROTOCOL",
                    object=ep.protocol,
                    object_type="PROTOCOL",
                    document_id=profile.document_id,
                    file_name=profile.file_name,
                    section_id=ep.section_id,
                    page=ep.page,
                )
            )
        if ep.section_id:
            rels.append(
                RelationRecord(
                    subject=node,
                    subject_type=role,
                    predicate="LOCATED_IN_SECTION",
                    object=ep.section_id,
                    object_type="SECTION_ID",
                    document_id=profile.document_id,
                    file_name=profile.file_name,
                    section_id=ep.section_id,
                    page=ep.page,
                )
            )
        for ek, ev in (ep.extras or {}).items():
            if not ev:
                continue
            rels.append(
                RelationRecord(
                    subject=node,
                    subject_type=role,
                    predicate=f"HAS_{ek.upper()}",
                    object=ev,
                    object_type="ATTRIBUTE",
                    document_id=profile.document_id,
                    file_name=profile.file_name,
                    section_id=ep.section_id,
                    page=ep.page,
                )
            )

    for f in profile.fields:
        key = f.field_key.lower()
        if "qos" in key:
            add("SUPPORTS_ROAMING", f.field_value, "QOS_PROFILE", f.section_id, f.page, f.field_key)
        if "effective date" in key:
            add("EFFECTIVE_FROM", f.field_value, "DATE", f.section_id, f.page)

    return rels


def relations_from_entities(
    entities: List[EntityRecord],
    file_name: str = "",
    operator_hint: str = "",
) -> List[RelationRecord]:
    """Lightweight co-occurrence relations from entity bags in the same section."""
    by_section: dict[str, list[EntityRecord]] = {}
    for e in entities:
        key = e.section_id or f"page:{e.page}" or "doc"
        by_section.setdefault(key, []).append(e)

    rels: List[RelationRecord] = []
    for sec_id, ents in by_section.items():
        nodes = [e for e in ents if e.type in {"NODE_TYPE", "HOSTNAME", "REALM"}]
        ips = [e for e in ents if e.type == "IP_ADDRESS"]
        protocols = [e for e in ents if e.type == "PROTOCOL"]
        tadigs = [e for e in ents if e.type == "TADIG"]
        subject = operator_hint or (tadigs[0].entity if tadigs else file_name)
        for n in nodes[:5]:
            for ip in ips[:5]:
                rels.append(
                    RelationRecord(
                        subject=n.entity,
                        subject_type=n.type,
                        predicate="HAS_IP",
                        object=ip.entity,
                        object_type="IP_ADDRESS",
                        document_id=n.document_id,
                        file_name=file_name,
                        section_id=n.section_id,
                        page=n.page,
                        source_text=n.source_text,
                        confidence=0.7,
                    )
                )
            for p in protocols[:3]:
                rels.append(
                    RelationRecord(
                        subject=n.entity,
                        subject_type=n.type,
                        predicate="USES_PROTOCOL",
                        object=p.entity,
                        object_type="PROTOCOL",
                        document_id=n.document_id,
                        file_name=file_name,
                        section_id=n.section_id,
                        page=n.page,
                        confidence=0.6,
                    )
                )
            if subject:
                rels.append(
                    RelationRecord(
                        subject=subject,
                        subject_type="OPERATOR",
                        predicate="HAS_ENDPOINT",
                        object=n.entity,
                        object_type=n.type,
                        document_id=n.document_id,
                        file_name=file_name,
                        section_id=n.section_id,
                        page=n.page,
                        confidence=0.6,
                    )
                )
    return rels
