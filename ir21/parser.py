"""Parse a RAEX IR.21 document into typed relational records.

Tables are identified by their header signature rather than by their position,
because Docling occasionally merges two template sections into one heading. The
IR.21 template fixes those headers, so the signature is a reliable key.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

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

# Marks a document as RAEX IR.21 rather than a prose specification.
_IR21_MARKERS = ("raex ir. 21", "raex ir.21", "tadig code", "ir. 21 data")

_SECTION_ID_RE = re.compile(r"Section\s*ID\s*:\s*(\d{1,2})\s*(?:\(([^)]*)\))?", re.I)
_EFFECTIVE_RE = re.compile(r"Effective date of change\s*:\s*([\d-]+)", re.I)
_KV_RE = re.compile(r"^\s*([^:]{2,60}?)\s*:\s*(.+?)\s*$")


def looks_like_ir21(canonical: dict[str, Any]) -> bool:
    """Whether an extracted document follows the RAEX IR.21 template."""
    blob = (canonical.get("title") or "").lower()
    for sec in (canonical.get("sections") or [])[:6]:
        blob += " " + (sec.get("title") or "").lower()
        blob += " " + " ".join(str(p).lower() for p in (sec.get("paragraphs") or [])[:8])
        for tbl in (sec.get("tables") or [])[:4]:
            blob += " " + " ".join(str(h).lower() for h in (tbl.get("headers") or []))
    return sum(m in blob for m in _IR21_MARKERS) >= 2


def _clean(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return "" if text.lower() in {"nan", "none", "-"} else text


def _cells(headers: list[str], row: Any) -> list[str]:
    if isinstance(row, dict):
        return [_clean(row.get(h, "")) for h in headers]
    return [_clean(v) for v in (row or [])]


def _looks_like_kv(cells: list[str]) -> bool:
    """A two-column row whose first cell is a trailing-colon label."""
    return len(cells) >= 2 and cells[0].endswith(":") and bool(cells[1])


def _table_rows(tbl: dict[str, Any]) -> list[list[str]]:
    """Body rows, including the header row when Docling promoted data into it."""
    headers = [str(h) for h in (tbl.get("headers") or [])]
    rows = [_cells(headers, r) for r in (tbl.get("rows") or [])]
    header_cells = [_clean(h) for h in headers]
    if _looks_like_kv(header_cells):
        rows.insert(0, header_cells)
    return [r for r in rows if any(c for c in r)]


def _collapse(cells: list[str]) -> list[str]:
    """Drop repeats produced by horizontally merged template cells.

    A cell spanning four columns is exported four times; the CAP version row
    ``CAPv1 CAPv2 CAPv3 | CAPv1 CAPv2 CAPv3 | CAPv2 | CAPv2`` really carries two
    values, one per roaming direction.
    """
    out: list[str] = []
    for cell in cells:
        if not out or cell != out[-1]:
            out.append(cell)
    return [c for c in out if c]


def _unwrap_host(value: str) -> str:
    """Rejoin a hostname split across lines inside a table cell.

    ``3gp pnetwork.org`` is a line wrap, whereas ``965 96909401`` is a real
    space between country code and number, so digit-space-digit is preserved.
    """
    if "." not in value or " " not in value:
        return value
    if re.search(r"\d\s+\d", value):
        return value
    if not re.fullmatch(r"[A-Za-z0-9.\-_:/]+(?:\s+[A-Za-z0-9.\-_:/]+)+", value):
        return value
    return re.sub(r"\s+", "", value)


def _header_blob(tbl: dict[str, Any]) -> str:
    return " | ".join(str(h) for h in (tbl.get("headers") or [])).lower()


def _first_col_blob(rows: list[list[str]]) -> str:
    return " ".join(r[0].lower() for r in rows[:6] if r)


def _section_meta(section: dict[str, Any]) -> tuple[str, str, str]:
    """Return (section_id, obligation, effective_date) declared in the section."""
    text = "\n".join(str(p) for p in (section.get("paragraphs") or []))
    for tbl in section.get("tables") or []:
        for row in _table_rows(tbl):
            text += "\n" + " ".join(row)
    sid, obligation, effective = "", "", ""
    m = _SECTION_ID_RE.search(text)
    if m:
        sid, obligation = m.group(1), (m.group(2) or "").strip()
    m = _EFFECTIVE_RE.search(text)
    if m:
        effective = m.group(1)
    return sid, obligation, effective


# A new "Label:" starting mid-line means two template fields were merged into
# one paragraph, e.g. "TADIG code: KWTMT Section ID: 1 (Mandatory)".
_INLINE_LABEL_RE = re.compile(r"(?<=\S)\s+(?=[A-Z][A-Za-z0-9 .\-/()]{2,40}:\s)")


def _kv_from_paragraphs(section: dict[str, Any]) -> Iterable[tuple[str, str]]:
    for para in section.get("paragraphs") or []:
        for piece in _INLINE_LABEL_RE.split(str(para)):
            m = _KV_RE.match(piece)
            if m:
                yield _clean(m.group(1)), _clean(m.group(2))


def _kv_from_section(section: dict[str, Any]) -> Iterable[tuple[str, str]]:
    """Label/value pairs from paragraphs and from two-column template rows."""
    yield from _kv_from_paragraphs(section)
    for tbl in section.get("tables") or []:
        for cells in _table_rows(tbl):
            if _looks_like_kv(cells):
                yield _clean(cells[0]).rstrip(":"), _clean(cells[1])


# --- table classification -------------------------------------------------


def _is_network_elements(hdr: str) -> bool:
    return "node type" in hdr and ("gt address" in hdr or "node id" in hdr)


def _is_change_history(hdr: str) -> bool:
    return "tadig code" in hdr and "description" in hdr and "date" in hdr


def _is_unused_sections(hdr: str) -> bool:
    return "tadig code" in hdr and "section name" in hdr


def _is_number_range(hdr: str) -> bool:
    return "sn range start" in hdr or ("number series" in hdr and "country code" in hdr)


def _is_map(hdr: str, section_title: str) -> bool:
    return "mobile application part" in section_title.lower() or (
        "interworking specifically for roaming" in hdr
    )


def _is_camel(hdr: str) -> bool:
    return "gsmssf" in hdr


def _is_diameter(hdr: str) -> bool:
    return "diameter edge agent" in hdr or ("ipx provider" in hdr and "realm" in hdr)


def _is_contact(hdr: str, first_col: str) -> bool:
    keys = ("person name", "team name", "jobtitle", "job title", "contact")
    return any(k in hdr for k in keys) or any(k in first_col for k in keys)


def _is_ip_resource(hdr: str) -> bool:
    return any(
        k in hdr
        for k in ("ip address range", "autonomous system number", "dns server", "grx provider")
    )


def _is_apn(hdr: str) -> bool:
    return hdr.startswith("apn") or "apn operator identifier" in hdr or "apn web list" in hdr


def _is_roaming_flag(hdr: str, first_col: str) -> bool:
    keys = ("s6a", "s6d", "s8 gtp", "sms delivery", "hpmn", "qci value", "roaming retry")
    return any(k in hdr for k in keys) or any(k in first_col for k in keys)


# --- per-table extraction -------------------------------------------------


def _parse_network_elements(
    tbl: dict[str, Any], rows: list[list[str]], sid: str
) -> list[NetworkElement]:
    headers = [str(h).lower() for h in (tbl.get("headers") or [])]

    def col(*names: str) -> Optional[int]:
        for i, h in enumerate(headers):
            if any(n in h for n in names):
                return i
        return None

    idx = {
        "node_type": col("node type"),
        "node_id": col("node id"),
        "gt": col("gt address"),
        "ip": col("ip address"),
        "vendor": col("vendor"),
        "sw": col("sw / hw", "sw/hw", "version"),
        "dual": col("dual access"),
        "loc": col("location"),
        "utc": col("utc offset"),
    }

    def get(cells: list[str], key: str) -> str:
        i = idx[key]
        return cells[i] if i is not None and i < len(cells) else ""

    out: list[NetworkElement] = []
    for cells in rows:
        node_type = get(cells, "node_type")
        if not node_type or node_type.lower() == "node type":
            continue
        out.append(
            NetworkElement(
                node_type=node_type,
                node_id=get(cells, "node_id"),
                gt_address=get(cells, "gt"),
                ip_address=get(cells, "ip"),
                vendor=get(cells, "vendor"),
                sw_hw_version=get(cells, "sw"),
                dual_access=get(cells, "dual"),
                location=get(cells, "loc"),
                utc_offset=get(cells, "utc"),
                section_id=sid or "13",
                page=tbl.get("page"),
            )
        )
    return out


_MAP_VERSION_RE = re.compile(r"^(?:MAPv\d|N/A|-)$", re.I)


def _parse_map(tbl: dict[str, Any], rows: list[list[str]], sid: str) -> list[MapVersion]:
    """MAP application contexts and their negotiated versions.

    Docling sometimes places the context name in the trailing column instead of
    the leading one, so the name is taken as the only cell that is not a version
    token rather than by position.
    """
    out: list[MapVersion] = []
    for cells in rows:
        padded = cells + [""] * (5 - len(cells))
        # Columns 1-3 always hold the versions; the name sits in the first or
        # last column depending on where Docling placed the merged cell.
        versions = padded[1:4]
        if any(v and not _MAP_VERSION_RE.match(v) for v in versions):
            continue
        name = padded[0] or padded[4]
        if not name or _MAP_VERSION_RE.match(name):
            continue
        out.append(
            MapVersion(
                application_context=name,
                inbound_msc_vlr=versions[0],
                inbound_sgsn=versions[1],
                outbound=versions[2],
                section_id=sid or "10",
                page=tbl.get("page"),
            )
        )
    return out


def _parse_camel(
    tbl: dict[str, Any], rows: list[list[str]], sid: str
) -> tuple[list[CamelSupport], list[CamelService], list[CamelFeature]]:
    node = _clean((tbl.get("headers") or ["gsmSSF/MSC"])[0]) or "gsmSSF/MSC"
    node = re.sub(r"\s*\(\d+\)$", "", node)
    support: list[CamelSupport] = []
    services: list[CamelService] = []
    features: list[CamelFeature] = []

    page = tbl.get("page")
    sid = sid or "15"
    group = ""
    mode = ""
    pending_directions: list[str] = []

    for cells in rows:
        merged = _collapse(cells)
        if not merged:
            continue
        first = merged[0]
        low = first.lower()

        if low.startswith("cap version supported"):
            pending_directions = [
                re.sub(r".*\(([^)]+)\).*", r"\1", c) for c in merged if "cap version" in c.lower()
            ]
            mode = "cap_versions"
            continue
        if mode == "cap_versions" and pending_directions:
            for direction, value in zip(pending_directions, merged):
                if value:
                    support.append(
                        CamelSupport(
                            node=node,
                            direction=direction,
                            cap_versions=value,
                            section_id=sid,
                            page=page,
                        )
                    )
            pending_directions = []
            mode = ""
            continue

        if low.startswith("service(s) name"):
            mode = "services"
            continue
        if low.startswith(("camel phase 4 csis", "functionalities")):
            group = first.rstrip(":")
            mode = "features"
            continue
        if low.startswith(("camel functionality information", "capv4 partial implementations")):
            mode = ""
            continue

        if mode == "services":
            padded = merged + [""] * (4 - len(merged))
            services.append(
                CamelService(
                    service_name=padded[0],
                    service_key=padded[1],
                    cap_version=padded[2],
                    scp_gt_addresses=padded[3],
                    section_id=sid,
                    page=page,
                )
            )
        elif mode == "features":
            padded = merged + [""] * (3 - len(merged))
            features.append(
                CamelFeature(
                    feature_group=group or "CAMEL Phase 4",
                    feature_name=padded[0],
                    supported=padded[1],
                    planned_date=padded[2],
                    section_id=sid,
                    page=page,
                )
            )
    return support, services, features


def _parse_number_ranges(
    tbl: dict[str, Any], rows: list[list[str]], sid: str
) -> list[NumberRange]:
    headers = [str(h) for h in (tbl.get("headers") or [])]
    default_type = _clean(headers[0]) if headers else "Number range"
    out: list[NumberRange] = []
    current = default_type
    for cells in rows:
        digits = [c for c in cells if re.fullmatch(r"[\d ]+", c or "")]
        label = cells[0] if cells else ""
        # A row with a label but no digits announces the range type that follows.
        if label and not re.fullmatch(r"[\d ]*", label):
            current = label
            if len(digits) < 2:
                continue
        values = [c for c in cells[1:] if c] if label and not label.isdigit() else [c for c in cells if c]
        values = [v for v in values if re.fullmatch(r"[\d ]+", v)]
        if not values:
            continue
        padded = values + [""] * (4 - len(values))
        out.append(
            NumberRange(
                range_type=current or default_type,
                cc=padded[0],
                ndc=padded[1],
                sn_start=padded[2],
                sn_stop=padded[3],
                section_id=sid or "4",
                page=tbl.get("page"),
            )
        )
    return out


def _parse_diameter(
    tbl: dict[str, Any], rows: list[list[str]], sid: str
) -> list[DiameterEndpoint]:
    hdr = _header_blob(tbl)
    out: list[DiameterEndpoint] = []
    if "ipx provider" in hdr:
        for cells in rows:
            padded = cells + [""] * (3 - len(cells))
            if not any(padded[:3]):
                continue
            out.append(
                DiameterEndpoint(
                    ipx_provider=padded[0],
                    realm=_unwrap_host(padded[1]),
                    architecture=padded[2],
                    section_id=sid or "20",
                    page=tbl.get("page"),
                )
            )
        return out

    for cells in rows:
        merged = [_unwrap_host(c) for c in cells if c]
        if not merged:
            continue
        fqdn = next((c for c in merged if re.search(r"[a-z]\.[a-z]", c, re.I)), "")
        ips = [c for c in merged if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", c)]
        if not fqdn and not ips:
            continue
        out.append(
            DiameterEndpoint(
                fqdn=fqdn,
                primary_ip=ips[0] if ips else "",
                secondary_ip=ips[1] if len(ips) > 1 else "",
                section_id=sid or "20",
                page=tbl.get("page"),
            )
        )
    return out


def _parse_roaming_flags(
    tbl: dict[str, Any], rows: list[list[str]], sid: str, section_title: str
) -> list[RoamingFlag]:
    headers = [_clean(h) for h in (tbl.get("headers") or [])]
    out: list[RoamingFlag] = []
    page = tbl.get("page")
    category = section_title or "Roaming"

    # Header-as-label layout: "S6a Supported without IWF.true"
    for head in headers:
        if "." in head and head.count(".") == 1:
            attr, _, val = head.partition(".")
            if attr and val and len(val) <= 24:
                out.append(
                    RoamingFlag(
                        category=category,
                        attribute=_clean(attr),
                        value=_clean(val),
                        section_id=sid or "20",
                        page=page,
                    )
                )

    header_pair = [h for h in headers if h and "." not in h]
    for cells in rows:
        merged = _collapse(cells)
        if len(merged) >= 2 and merged[0]:
            out.append(
                RoamingFlag(
                    category=category,
                    attribute=merged[0],
                    value=merged[1],
                    counterpart=merged[2] if len(merged) > 2 else "",
                    section_id=sid or "20",
                    page=page,
                )
            )
        elif len(merged) == 1 and len(header_pair) >= 2:
            out.append(
                RoamingFlag(
                    category=category,
                    attribute=header_pair[0],
                    value=merged[0],
                    section_id=sid or "20",
                    page=page,
                )
            )
    return out


def _parse_ip_resources(
    tbl: dict[str, Any], rows: list[list[str]], sid: str
) -> list[IpResource]:
    headers = [_clean(h) for h in (tbl.get("headers") or [])]
    kind = headers[0].rstrip(":") if headers else "IP resource"
    out: list[IpResource] = []
    for cells in rows:
        merged = [c for c in cells if c]
        if not merged:
            continue
        value = merged[-1] if len(merged) == 1 else merged[0]
        label = merged[1] if len(merged) > 1 else ""
        if value.rstrip(":").lower() == kind.lower():
            continue
        out.append(
            IpResource(
                kind=kind,
                value=value,
                label=label,
                section_id=sid or "17",
                page=tbl.get("page"),
            )
        )
    return out


def _parse_apn(tbl: dict[str, Any], rows: list[list[str]], sid: str) -> list[Apn]:
    headers = [_clean(h) for h in (tbl.get("headers") or [])]
    list_type = headers[0].split(".")[0] if headers else "APN"
    out: list[Apn] = []
    for cells in rows:
        merged = [c for c in cells if c]
        if not merged:
            continue
        apn = merged[0]
        url = next((c for c in merged if c.startswith("http")), "")
        ip = next((c for c in merged if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", c)), "")
        out.append(
            Apn(
                list_type=list_type,
                apn=apn,
                username=merged[1] if len(merged) > 1 else "",
                password=merged[2] if len(merged) > 2 else "",
                gateway_ip=ip,
                server_url=url,
                section_id=sid or "16",
                page=tbl.get("page"),
            )
        )
    return out


def _parse_contacts(
    tbl: dict[str, Any], rows: list[list[str]], sid: str, section_title: str
) -> list[Contact]:
    headers = [_clean(h) for h in (tbl.get("headers") or [])]
    category = re.sub(r"\s*\(\d+\)$", "", headers[0]) if headers else section_title
    out: list[Contact] = []
    email_re = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
    phone_re = re.compile(r"\+?\d[\d ]{6,}")
    label = ""
    for cells in rows:
        merged = _collapse(cells)
        if not merged:
            continue
        head = merged[0].lower()
        if head in {"person name", "team name", "jobtitle", "job title"}:
            label = merged[0]
            continue
        if head.endswith("contact") or head.startswith(("list of", "main contact", "escalation", "24 x 7")):
            category = merged[0]
            continue
        emails = [c for c in merged if email_re.fullmatch(c)]
        phones = [c for c in merged if phone_re.fullmatch(c)]
        # Rows such as "Location | Kuwait" sit inside the contact block but are
        # settings, not people; without a phone or an address they are facts.
        if not emails and not phones:
            continue
        name = merged[0] if merged[0] not in emails + phones else ""
        is_team = "team" in label.lower()
        out.append(
            Contact(
                category=category or section_title,
                person_name="" if is_team else name,
                team_name=name if is_team else "",
                job_title=label if label.lower() in {"jobtitle", "job title"} else "",
                tel=phones[0] if phones else "",
                mobile=phones[1] if len(phones) > 1 else "",
                fax=phones[2] if len(phones) > 2 else "",
                email=emails[0] if emails else "",
                section_id=sid or "21",
                page=tbl.get("page"),
            )
        )
    return out


def _parse_change_history(tbl: dict[str, Any], rows: list[list[str]]) -> list[ChangeHistory]:
    out: list[ChangeHistory] = []
    for cells in rows:
        padded = cells + [""] * (5 - len(cells))
        if padded[0].lower() == "tadig code":
            continue
        date = next((c for c in padded if re.fullmatch(r"\d{4}-\d{2}-\d{2}", c)), "")
        if not date:
            continue
        out.append(
            ChangeHistory(
                change_date=date,
                section_id=padded[1],
                section_name=padded[2],
                description=padded[4] or padded[3],
                page=tbl.get("page"),
            )
        )
    return out


def _parse_unused(tbl: dict[str, Any], rows: list[list[str]]) -> list[UnusedSection]:
    out: list[UnusedSection] = []
    for cells in rows:
        padded = cells + [""] * (3 - len(cells))
        if not padded[1] or padded[1].lower() == "section id":
            continue
        out.append(UnusedSection(section_id=padded[1], section_name=padded[2]))
    return out


def _facts_from_table(
    tbl: dict[str, Any], rows: list[list[str]], sid: str, section_title: str
) -> list[Fact]:
    """Key/value fallback so unmatched tables still land in the database."""
    headers = [_clean(h) for h in (tbl.get("headers") or [])]
    prefix = headers[0].rstrip(":") if headers else ""
    out: list[Fact] = []
    for cells in rows:
        merged = _collapse(cells)
        if len(merged) < 2:
            continue
        key = merged[0].rstrip(":")
        value = " | ".join(merged[1:])
        if not key or not value or key == value:
            continue
        if prefix and prefix.lower() != key.lower():
            key = f"{prefix} — {key}"
        out.append(
            Fact(
                field_key=key,
                field_value=value,
                section_id=sid,
                section_title=section_title,
                page=tbl.get("page"),
            )
        )
    return out


def parse_ir21(canonical: dict[str, Any], document_id: str, file_name: str) -> Dataset:
    """Build the relational dataset for one IR.21 document."""
    doc = Document(document_id=document_id, file_name=file_name)
    data = Dataset(document=doc)
    pages: list[int] = []

    for section in canonical.get("sections") or []:
        title = _clean(section.get("title"))
        sid, obligation, effective = _section_meta(section)
        page = section.get("page_start")
        if page:
            pages.append(int(page))
        if sid:
            data.sections.append(
                Section(
                    section_id=sid,
                    title=title,
                    obligation=obligation,
                    effective_date=effective,
                    page=page,
                )
            )

        paragraph_keys = {k.lower() for k, _ in _kv_from_paragraphs(section)}
        for key, value in _kv_from_section(section):
            low = key.lower()
            if low == "tadig code" and not doc.tadig:
                doc.tadig = value
            elif low == "organisation name":
                doc.organisation_name = value
            elif low == "country initials":
                doc.country_initials = value
            elif low == "network type":
                doc.network_type = value
            elif low.startswith("presentation of country initials"):
                doc.presentation_name = value
            elif low == "abbreviated mnn":
                doc.abbreviated_mnn = value
            elif low == "creation date":
                doc.creation_date = value
            elif low == "creation time":
                doc.creation_time = value
            elif low.startswith("tadig-gen schema"):
                doc.tadig_gen_schema = value
            elif low.startswith("raex-ir.21 schema"):
                doc.raex_schema = value
            elif not low.startswith("section id") and low in paragraph_keys:
                # Table-borne pairs are recorded by the table pass below.
                data.facts.append(
                    Fact(
                        field_key=key,
                        field_value=value,
                        section_id=sid,
                        section_title=title,
                        page=page,
                    )
                )

        for tbl in section.get("tables") or []:
            rows = _table_rows(tbl)
            if not rows:
                continue
            hdr = _header_blob(tbl)
            first_col = _first_col_blob(rows)
            if tbl.get("page"):
                pages.append(int(tbl["page"]))

            if _is_network_elements(hdr):
                data.network_elements.extend(_parse_network_elements(tbl, rows, sid))
            elif _is_change_history(hdr):
                data.change_history.extend(_parse_change_history(tbl, rows))
            elif _is_unused_sections(hdr):
                data.unused_sections.extend(_parse_unused(tbl, rows))
            elif _is_camel(hdr):
                support, services, features = _parse_camel(tbl, rows, sid)
                data.camel_support.extend(support)
                data.camel_services.extend(services)
                data.camel_features.extend(features)
            elif _is_map(hdr, title):
                data.map_versions.extend(_parse_map(tbl, rows, sid))
            elif _is_number_range(hdr):
                data.number_ranges.extend(_parse_number_ranges(tbl, rows, sid))
            elif _is_diameter(hdr):
                data.diameter_endpoints.extend(_parse_diameter(tbl, rows, sid))
            elif _is_ip_resource(hdr):
                data.ip_resources.extend(_parse_ip_resources(tbl, rows, sid))
            elif _is_apn(hdr):
                data.apns.extend(_parse_apn(tbl, rows, sid))
            elif _is_contact(hdr, first_col):
                data.contacts.extend(_parse_contacts(tbl, rows, sid, title))
            elif _is_roaming_flag(hdr, first_col):
                data.roaming_flags.extend(_parse_roaming_flags(tbl, rows, sid, title))
            else:
                data.facts.extend(_facts_from_table(tbl, rows, sid, title))

            # MCC/MNC live in the E.212 table and identify the network.
            if "mobile country code" in hdr:
                for cells in rows:
                    nums = [c for c in cells if re.fullmatch(r"\d{2,3}", c)]
                    if len(nums) >= 2:
                        doc.mcc, doc.mnc = nums[0], nums[1]

    doc.page_count = max(pages) if pages else None
    _dedupe(data)
    return data


def _dedupe(data: Dataset) -> None:
    """Drop duplicate rows that come from repeated template blocks."""
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
