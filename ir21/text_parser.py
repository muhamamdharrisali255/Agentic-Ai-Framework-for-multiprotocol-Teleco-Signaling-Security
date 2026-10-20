"""Parse RAEX IR.21 plain text (template 9.2) into relational records.

Docling table extraction is unreliable on this form: merged cells, repeated
headers, and page furniture. The GSMA template itself is regular enough to
parse from the extracted text, which is what this module does.
"""

from __future__ import annotations

import re
from typing import Iterable

from ir21.records import (
    Apn,
    CamelFeature,
    CamelService,
    CamelSupport,
    ChangeHistory,
    Contact,
    Dataset,
    DiameterEndpoint,
    Document,
    Fact,
    IpResource,
    MapVersion,
    NetworkElement,
    NumberRange,
    RoamingFlag,
    Section,
    UnusedSection,
)

_SECTION_TITLES = (
    "ORGANISATION INFORMATION",
    "History of changes",
    "NETWORK INFORMATION",
    "NETWORK",
    "ROUTING INFORMATION",
    "INTERNATIONAL SCCP GATEWAY",
    "SUBSCRIBER IDENTITY AUTHENTICATION",
    "MOBILE APPLICATION PART (MAP)",
    "NETWORK ELEMENTS INFORMATION",
    "CAMEL INFO",
    "Packet Data Services Information",
    "IP - Roaming and IP - Interworking Information",
    "MMS Interworking Information",
    "LTE Roaming Information",
    "LTE Information",
    "CONTACT INFORMATION",
    "SECTIONS NOT IN USE",
)

_FURNITURE = re.compile(
    r"(?:RAEX IR\. ?21 template ver\. [\d.]+|GSMA Roaming Database|IR\. ?21 Data|"
    r"Page \d+ of \d+)",
    re.I,
)

_NODE_TYPES = (
    "MSC/VLR-2G+3G",
    "SGSN-2G+3G",
    "MSC/VLR",
    "Test SGSN",
    "Test HSS",
    "Test SMSC",
    "Test MMSC",
    "HSS",
    "HLR",
    "MMSC",
    "SMSC",
    "SCP",
    "SGSN",
    "BSC",
    "IN",
    "Other",
)

_GT_RE = re.compile(r"\b(\d{2,3})\s+(\d{5,12})\b")
_CAP_RE = re.compile(r"CAPv\d+", re.I)
_MAP_VER_RE = re.compile(r"^(MAPv\d+|N/A|-)$", re.I)
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
_TADIG_RE = re.compile(r"\b([A-Z]{5})\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?\b"
)


def looks_like_ir21_text(text: str) -> bool:
    blob = (text or "").lower()
    return sum(
        m in blob
        for m in ("raex ir. 21", "raex ir.21", "tadig code", "ir. 21 data", "gsma roaming database")
    ) >= 2


def split_ir21_documents(text: str) -> list[str]:
    """One RAEX filing can be concatenated after another in a dump."""
    starts = [
        m.start()
        for m in re.finditer(r"ORGANISATION INFORMATION\s+TADIG code\s*:", text, re.I)
    ]
    if len(starts) <= 1:
        return [text]
    parts: list[str] = []
    for i, start in enumerate(starts):
        # Include the cover page sitting just before ORGANISATION INFORMATION.
        cover = text.rfind("GSMA Roaming Database", 0, start)
        begin = cover if cover >= 0 else start
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        # Don't steal the next cover page.
        if i + 1 < len(starts):
            prev_cover = text.rfind("GSMA Roaming Database", start, starts[i + 1])
            if prev_cover > start:
                end = prev_cover
        parts.append(text[begin:end].strip())
    return [p for p in parts if p]


def parse_ir21_text(text: str, file_name: str, document_id: str = "pending") -> Dataset:
    """Build a Dataset from one RAEX IR.21 text dump."""
    cleaned = _strip_furniture(text)
    sections = _split_sections(cleaned)
    doc = Document(document_id=document_id, file_name=file_name)
    data = Dataset(document=doc)

    _fill_document(doc, sections)
    for title, body, page in sections:
        sid = _section_id(body) or _section_id_from_title(title)
        if sid:
            data.sections.append(
                Section(
                    section_id=sid,
                    title=title,
                    obligation=_obligation(body),
                    effective_date=_effective_date(body),
                    page=page,
                )
            )
        key = title.upper()
        if "HISTORY OF CHANGES" in key:
            data.change_history.extend(_parse_history(body, page))
        elif "NETWORK ELEMENTS" in key:
            data.network_elements.extend(_parse_network_elements(body, sid or "13", page))
        elif "CAMEL" in key:
            support, services, features = _parse_camel(body, sid or "15", page)
            data.camel_support.extend(support)
            data.camel_services.extend(services)
            data.camel_features.extend(features)
        elif "MOBILE APPLICATION PART" in key or key.endswith("MAP)"):
            data.map_versions.extend(_parse_map(body, sid or "10", page))
        elif "ROUTING" in key:
            data.number_ranges.extend(_parse_number_ranges(body, sid or "4", page))
            _fill_mcc_mnc(doc, body)
        elif "LTE ROAMING" in key:
            data.diameter_endpoints.extend(_parse_diameter(body, sid or "20", page))
            data.roaming_flags.extend(_parse_roaming_flags(body, sid or "20", page, title))
        elif "LTE INFORMATION" in key:
            data.roaming_flags.extend(_parse_qci(body, sid or "20", page))
        elif "IP - ROAMING" in key or "INTERWORKING INFORMATION" in key and "IP" in key:
            data.ip_resources.extend(_parse_ip_resources(body, sid or "17", page))
        elif "PACKET DATA" in key:
            data.apns.extend(_parse_apns(body, sid or "16", page))
            data.facts.extend(_kv_facts(body, sid or "16", title, page))
        elif "CONTACT" in key:
            data.contacts.extend(_parse_contacts(body, sid or "21", page))
        elif "NOT IN USE" in key:
            data.unused_sections.extend(_parse_unused(body))
        elif "AUTHENTICATION" in key:
            data.facts.extend(_kv_facts(body, sid or "8", title, page))
        else:
            data.facts.extend(_kv_facts(body, sid, title, page))

    _dedupe(data)
    return data


def parse_all(text: str, file_name: str) -> list[Dataset]:
    """Parse one or more concatenated RAEX filings."""
    out: list[Dataset] = []
    for i, part in enumerate(split_ir21_documents(text)):
        ds = parse_ir21_text(part, file_name=file_name, document_id=f"pending-{i}")
        tadig = ds.document.tadig or f"DOC{i}"
        ds.document.document_id = f"IR21-{tadig.upper()}"
        if len(split_ir21_documents(text)) > 1:
            stem = file_name.rsplit(".", 1)[0]
            ds.document.file_name = f"{stem}_{tadig}.txt"
        out.append(ds)
    return out


# --- cleaning / sectioning ------------------------------------------------


def _strip_furniture(text: str) -> str:
    lines = []
    for raw in (text or "").splitlines():
        line = _FURNITURE.sub(" ", raw)
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def _split_sections(text: str) -> list[tuple[str, str, int | None]]:
    """Return (title, body, first_page_hint) for each known template section."""
    pattern = re.compile(
        r"^(" + "|".join(re.escape(t) for t in sorted(_SECTION_TITLES, key=len, reverse=True)) + r")\s*$",
        re.I | re.M,
    )
    matches = list(pattern.finditer(text))
    if not matches:
        return [("DOCUMENT", text, None)]
    sections: list[tuple[str, str, int | None]] = []
    if matches[0].start() > 0:
        preamble = text[: matches[0].start()].strip()
        if preamble:
            sections.append(("RAEX IR. 21 Information", preamble, 1))
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[m.end() : end].strip()
        page = _first_page(body)
        sections.append((title, body, page))
    return sections


def _first_page(body: str) -> int | None:
    m = re.search(r"\b[Pp]age\s+(\d+)", body)
    return int(m.group(1)) if m else None


def _section_id(body: str) -> str:
    m = re.search(r"Section ID\s*:\s*(\d{1,2})", body, re.I)
    return m.group(1) if m else ""


def _section_id_from_title(title: str) -> str:
    mapping = {
        "ORGANISATION INFORMATION": "1",
        "NETWORK": "2",
        "NETWORK INFORMATION": "3",
        "ROUTING INFORMATION": "4",
        "INTERNATIONAL SCCP GATEWAY": "5",
        "SUBSCRIBER IDENTITY AUTHENTICATION": "8",
        "MOBILE APPLICATION PART (MAP)": "10",
        "NETWORK ELEMENTS INFORMATION": "13",
        "CAMEL INFO": "15",
        "PACKET DATA SERVICES INFORMATION": "16",
        "IP - ROAMING AND IP - INTERWORKING INFORMATION": "17",
        "MMS INTERWORKING INFORMATION": "18",
        "LTE ROAMING INFORMATION": "20",
        "CONTACT INFORMATION": "21",
    }
    return mapping.get(title.upper(), "")


def _obligation(body: str) -> str:
    m = re.search(r"Section ID\s*:\s*\d+\s*\(([^)]*)\)", body, re.I)
    return (m.group(1) or "").strip()


def _effective_date(body: str) -> str:
    m = re.search(r"Effective date of change\s*:\s*([\d-]+)", body, re.I)
    return m.group(1) if m else ""


def _kv_pairs(body: str) -> Iterable[tuple[str, str]]:
    for piece in re.split(r"(?<=\S)\s+(?=[A-Z][A-Za-z0-9 .\-/()]{2,40}:\s)", body):
        m = re.match(r"\s*([^:]{2,60}?)\s*:\s*(.+?)\s*$", piece)
        if m:
            yield m.group(1).strip(), m.group(2).strip()
    for line in body.splitlines():
        m = re.match(r"\s*([^:]{2,60}?)\s*:\s*(.+?)\s*$", line)
        if m:
            yield m.group(1).strip(), m.group(2).strip()


def _fill_document(doc: Document, sections: list[tuple[str, str, int | None]]) -> None:
    blob = "\n".join(b for _, b, _ in sections)
    for key, value in _kv_pairs(blob):
        low = key.lower()
        if low == "tadig code" and not doc.tadig:
            m = _TADIG_RE.search(value.upper())
            doc.tadig = m.group(1) if m else value.strip().upper()[:5]
        elif low == "organisation name":
            doc.organisation_name = value
        elif low == "country initials":
            doc.country_initials = value.split()[0]
        elif low == "network type":
            doc.network_type = value
        elif "presentation of country initials" in low:
            doc.presentation_name = value
        elif low == "abbreviated mnn":
            doc.abbreviated_mnn = value
        elif low == "creation date":
            doc.creation_date = value.split()[0]
        elif low == "creation time":
            doc.creation_time = value
        elif "tadig-gen schema" in low:
            doc.tadig_gen_schema = value
        elif "raex-ir.21 schema" in low:
            doc.raex_schema = value
    _fill_mcc_mnc(doc, blob)


def _fill_mcc_mnc(doc: Document, body: str) -> None:
    if doc.mcc and doc.mnc:
        return
    m = re.search(
        r"E\.\s*212.*?Mobile Country Code.*?Mobile Network Code.*?\n\s*(\d{3})\s+(\d{2,3})",
        body,
        re.I | re.S,
    )
    if m:
        doc.mcc, doc.mnc = m.group(1), m.group(2)


# --- network elements -----------------------------------------------------


def _parse_network_elements(body: str, sid: str, page: int | None) -> list[NetworkElement]:
    # Re-join a node type split across lines: "MSC/" + "VLR-2G+3G"
    text = re.sub(r"MSC/\s*\n\s*VLR", "MSC/VLR", body)
    text = re.sub(r"\n+", "\n", text)
    out: list[NetworkElement] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("node type"):
            continue
        if pending:
            line = f"{pending} {line}"
            pending = ""
        if line.rstrip("/").upper() in {"MSC", "MSC/"} or line.upper() in {"MSC/", "VLR-2G+3G"}:
            pending = line.rstrip()
            continue
        parsed = _parse_ne_line(line, sid, page)
        if parsed:
            out.append(parsed)
        elif any(line.upper().startswith(t) for t in _NODE_TYPES) and not _GT_RE.search(line):
            pending = line
    return out


def _parse_ne_line(line: str, sid: str, page: int | None) -> NetworkElement | None:
    node_type = ""
    rest = line
    for nt in _NODE_TYPES:
        if rest.upper().startswith(nt.upper()):
            node_type = nt if nt != "Test SGSN" else "SGSN-2G+3G"
            rest = rest[len(nt) :].strip()
            if nt.startswith("Test"):
                # "Test SGSN" / "Test HSS" is the node id, type already set.
                rest = f"{nt} {rest}".strip()
                if nt == "Test SGSN":
                    node_type = "SGSN-2G+3G"
                elif nt == "Test HSS":
                    node_type = "HSS"
                elif nt == "Test SMSC":
                    node_type = "SMSC"
                elif nt == "Test MMSC":
                    node_type = "MMSC"
            break
    if not node_type:
        return None
    utc = ""
    m_utc = re.search(r"([+-]\d{2}:\d{2})", rest)
    if m_utc:
        utc = m_utc.group(1)
        rest = (rest[: m_utc.start()] + rest[m_utc.end() :]).strip()
    vendors = ("Huawei", "NSN", "Ericsson", "Acision", "Roamware", "Nokia", "ZTE", "Cisco")
    vendor = ""
    for v in vendors:
        if re.search(rf"\b{re.escape(v)}\b", rest, re.I):
            vendor = v
            rest = re.sub(rf"\b{re.escape(v)}\b", " ", rest, flags=re.I).strip()
            break
    gt = ""
    m_gt = _GT_RE.search(rest)
    if m_gt:
        gt = f"{m_gt.group(1)} {m_gt.group(2)}"
        rest = (rest[: m_gt.start()] + rest[m_gt.end() :]).strip()
    rest = re.sub(r"\b[01]\b", " ", rest)
    rest = re.sub(r"\s+", " ", rest).strip()
    node_id = rest
    if not gt and not node_id:
        return None
    return NetworkElement(
        node_type=node_type,
        node_id=node_id,
        gt_address=gt,
        vendor=vendor,
        utc_offset=utc,
        section_id=sid,
        page=page,
    )


# --- CAMEL ----------------------------------------------------------------


def _parse_camel(
    body: str, sid: str, page: int | None
) -> tuple[list[CamelSupport], list[CamelService], list[CamelFeature]]:
    support: list[CamelSupport] = []
    services: list[CamelService] = []
    features: list[CamelFeature] = []

    node = "gsmSSF/MSC"
    m_node = re.search(r"\b(gsmSSF/MSC|gprsSSF/SGSN|imsSSF)\b", body, re.I)
    if m_node:
        node = m_node.group(1)

    # Template: inbound versions occupy the left columns, outbound the last CAP token.
    cap_line = None
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if "CAP Version supported" in line and i + 1 < len(lines):
            cap_line = lines[i + 1]
            break
    if cap_line is None:
        blob = " ".join(lines)
        caps = _CAP_RE.findall(blob)
        if caps:
            cap_line = " ".join(caps)
    if cap_line:
        caps = _CAP_RE.findall(cap_line)
        if len(caps) >= 2:
            support.append(
                CamelSupport(
                    node=node, direction="Inbound", cap_versions=" ".join(caps[:-1]),
                    section_id=sid, page=page,
                )
            )
            support.append(
                CamelSupport(
                    node=node, direction="Outbound", cap_versions=caps[-1],
                    section_id=sid, page=page,
                )
            )
        elif len(caps) == 1:
            support.append(
                CamelSupport(
                    node=node, direction="Inbound", cap_versions=caps[0],
                    section_id=sid, page=page,
                )
            )

    # Services: name / SK / CAP / SCP GTs
    svc_blob = re.search(
        r"Service\(s\) Name.*?(?=CAPv4 Partial|CAMEL Phase 4|$)",
        body,
        re.I | re.S,
    )
    if svc_blob:
        block = svc_blob.group(0)
        current: list[str] = []
        for line in block.splitlines()[1:]:
            line = line.strip()
            if not line or line.lower().startswith("service"):
                continue
            current.append(line)
            joined = " ".join(current)
            caps = _CAP_RE.findall(joined)
            gts = [" ".join(m) for m in _GT_RE.findall(joined)]
            sk = re.search(r"\b(\d{1,3})\b", joined)
            if caps and (gts or sk):
                name = re.split(r"\bCAPv|\b\d{2,3}\s+\d", joined, maxsplit=1)[0].strip(" -")
                services.append(
                    CamelService(
                        service_name=name or joined[:80],
                        service_key=sk.group(1) if sk else "",
                        cap_version=caps[0],
                        scp_gt_addresses=" ".join(gts),
                        section_id=sid,
                        page=page,
                    )
                )
                current = []

    group = ""
    for line in body.splitlines():
        low = line.strip().lower()
        if low.startswith("camel phase 4") or low.startswith("functionalities"):
            group = line.strip().rstrip(":")
            continue
        if group and line.strip() and not line.strip().endswith(":"):
            name = re.sub(r"\s+(Yes|No|Supported).*$", "", line.strip(), flags=re.I)
            if 2 < len(name) < 60 and not name.lower().startswith(("supported", "planned")):
                features.append(
                    CamelFeature(
                        feature_group=group,
                        feature_name=name,
                        section_id=sid,
                        page=page,
                    )
                )
    return support, services, features


# --- MAP ------------------------------------------------------------------


def _parse_map(body: str, sid: str, page: int | None) -> list[MapVersion]:
    out: list[MapVersion] = []
    for line in body.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        versions = parts[-3:]
        if not all(_MAP_VER_RE.match(v) for v in versions):
            continue
        name = " ".join(parts[:-3])
        if not name or name.lower().startswith("application"):
            continue
        out.append(
            MapVersion(
                application_context=name,
                inbound_msc_vlr=versions[0],
                inbound_sgsn=versions[1],
                outbound=versions[2],
                section_id=sid,
                page=page,
            )
        )
    return out


# --- number ranges --------------------------------------------------------


def _parse_number_ranges(body: str, sid: str, page: int | None) -> list[NumberRange]:
    out: list[NumberRange] = []
    current = "MSISDN number ranges"
    for line in body.splitlines():
        stripped = line.strip()
        if re.search(r"number range", stripped, re.I) or stripped.endswith("(s)"):
            current = stripped
            continue
        nums = stripped.split()
        if not nums or not all(n.isdigit() for n in nums):
            continue
        padded = nums + [""] * (4 - len(nums))
        out.append(
            NumberRange(
                range_type=current,
                cc=padded[0],
                ndc=padded[1],
                sn_start=padded[2],
                sn_stop=padded[3],
                section_id=sid,
                page=page,
            )
        )
    return out


# --- diameter / LTE -------------------------------------------------------


def _parse_diameter(body: str, sid: str, page: int | None) -> list[DiameterEndpoint]:
    out: list[DiameterEndpoint] = []
    ips = _IPV4_RE.findall(body)
    # FQDN lines are often wrapped: "ssb-dra1.ims....3gp" + "pnetwork.org"
    joined = re.sub(r"(\S)\n(\S)", r"\1\2", body)
    joined = re.sub(r"3gp\s*pnetwork", "3gppnetwork", joined, flags=re.I)
    fqdns = [
        m.group(0).rstrip(".")
        for m in re.finditer(
            r"\b[a-z0-9][a-z0-9.-]{6,}\.(?:org|grx|net|com)\b", joined, re.I
        )
    ]
    # Pair successive FQDNs with nearby IPs when the DEA table lists them together.
    seen: set[str] = set()
    for i, fqdn in enumerate(fqdns):
        key = fqdn.lower()
        if key in seen:
            continue
        seen.add(key)
        primary = ips[i * 2] if i * 2 < len(ips) else (ips[0] if ips else "")
        secondary = ips[i * 2 + 1] if i * 2 + 1 < len(ips) else ""
        if not re.search(r"dra|dea|epc|ims", fqdn, re.I) and i > 1:
            continue
        out.append(
            DiameterEndpoint(
                fqdn=fqdn,
                primary_ip=primary,
                secondary_ip=secondary,
                section_id=sid,
                page=page,
            )
        )
    ipx = re.search(r"IPX Provider Name\s+(\S+)", body, re.I)
    realm = re.search(r"IPX DEA Realm Used\s+(\S+)", body, re.I)
    arch = re.search(r"Diameter Architecture\s+(\S+)", body, re.I)
    if ipx or realm:
        out.insert(
            0,
            DiameterEndpoint(
                ipx_provider=ipx.group(1) if ipx else "",
                realm=realm.group(1) if realm else "",
                architecture=arch.group(1) if arch else "",
                primary_ip=ips[0] if ips else "",
                secondary_ip=ips[1] if len(ips) > 1 else "",
                section_id=sid,
                page=page,
            ),
        )
    return out


def _parse_roaming_flags(body: str, sid: str, page: int | None, title: str) -> list[RoamingFlag]:
    out: list[RoamingFlag] = []
    for m in re.finditer(
        r"(S6a Supported without IWF|S6a MAP IWF supported to HSS|"
        r"S6a MAP IWF supported to MME|S6d used for legacy SGSN|"
        r"S8 GTP interface available|S8 PMIP interface available|"
        r"S9 used for PCC|SMS delivery over IP|SMS delivery over SGs|"
        r"Is Roaming Retry supported\?)\s+(true|false|Yes|No)",
        body,
        re.I,
    ):
        out.append(
            RoamingFlag(
                category=title,
                attribute=m.group(1),
                value=m.group(2),
                section_id=sid,
                page=page,
            )
        )
    return out


def _parse_qci(body: str, sid: str, page: int | None) -> list[RoamingFlag]:
    out: list[RoamingFlag] = []
    for m in re.finditer(r"QCI Value (\d) Supported\s+(Yes|No)", body, re.I):
        out.append(
            RoamingFlag(
                category="LTE Information",
                attribute=f"QCI Value {m.group(1)} Supported",
                value=m.group(2),
                section_id=sid,
                page=page,
            )
        )
    return out


def _parse_ip_resources(body: str, sid: str, page: int | None) -> list[IpResource]:
    out: list[IpResource] = []
    for ip in _IPV4_RE.findall(body):
        kind = "IP Address Range" if "/" in ip else "IP address"
        if re.search(rf"{re.escape(ip)}\s+(Primary|Secondary)", body, re.I):
            kind = "DNS"
        out.append(IpResource(kind=kind, value=ip, section_id=sid, page=page))
    for m in re.finditer(r"\bASN\b\s+(\d{4,6})", body):
        out.append(IpResource(kind="ASN", value=m.group(1), section_id=sid, page=page))
    for m in re.finditer(
        r"(Aicent|BICS|Syniverse|BELGACOM-BELGIUM(?:\s+\(BICS\))?|Telstra)\s*(?:\((\d+)\))?",
        body,
        re.I,
    ):
        label = m.group(1)
        value = m.group(2) or label
        out.append(IpResource(kind="GRX Provider", value=value, label=label, section_id=sid, page=page))
    return out


def _parse_apns(body: str, sid: str, page: int | None) -> list[Apn]:
    out: list[Apn] = []
    for m in re.finditer(r"\b(mnc\d{2,3}\.mcc\d{3}\.[a-z0-9.]+)\b", body, re.I):
        out.append(Apn(list_type="APN Operator Identifier", apn=m.group(1), section_id=sid, page=page))
    return out


def _parse_contacts(body: str, sid: str, page: int | None) -> list[Contact]:
    out: list[Contact] = []
    for email in _EMAIL_RE.findall(body):
        out.append(Contact(category="Contact", email=email, section_id=sid, page=page))
    return out


def _parse_history(body: str, page: int | None) -> list[ChangeHistory]:
    out: list[ChangeHistory] = []
    tadig = ""
    m_t = _TADIG_RE.search(body[:40] + " " + body)
    # Rows: TADIG  section_id  section_name  date  description
    for m in re.finditer(
        r"\b([A-Z]{5})\s+(\d{1,2})\s+(.+?)\s+(\d{4}-\d{2}-\d{2})\s+(.+?)(?=\n[A-Z]{5}\s+\d|\Z)",
        body,
        re.S,
    ):
        tadig = m.group(1)
        out.append(
            ChangeHistory(
                change_date=m.group(4),
                section_id=m.group(2),
                section_name=re.sub(r"\s+", " ", m.group(3)).strip(),
                description=re.sub(r"\s+", " ", m.group(5)).strip(),
                page=page,
            )
        )
    if not out:
        for m in re.finditer(
            r"(\d{4}-\d{2}-\d{2})\s+(.+)",
            body,
        ):
            out.append(
                ChangeHistory(
                    change_date=m.group(1),
                    description=m.group(2).strip(),
                    page=page,
                )
            )
    return out


def _parse_unused(body: str) -> list[UnusedSection]:
    out: list[UnusedSection] = []
    for m in re.finditer(r"\b[A-Z]{5}\s+(\d{1,2})\s+(.+)", body):
        out.append(UnusedSection(section_id=m.group(1), section_name=m.group(2).strip()))
    return out


def _kv_facts(body: str, sid: str, title: str, page: int | None) -> list[Fact]:
    out: list[Fact] = []
    for key, value in _kv_pairs(body):
        if key.lower().startswith("section id") or key.lower() == "tadig code":
            continue
        if not value or value.lower() in {"nan", "-", "none"}:
            continue
        out.append(
            Fact(
                field_key=key,
                field_value=value,
                section_id=sid,
                section_title=title,
                page=page,
            )
        )
    return out


def _dedupe(data: Dataset) -> None:
    for name in data.counts():
        items = getattr(data, name)
        seen: set[tuple] = set()
        unique = []
        for item in items:
            key = tuple(sorted(vars(item).items()))
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        setattr(data, name, unique)
