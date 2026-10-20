"""Extract normalized IR.21 structured profile from a CanonicalDocument."""

from __future__ import annotations

import re
from typing import Any, Optional

from shared.ir21_schema import (
    IR21_SECTION_MAP,
    IR21Endpoint,
    IR21Field,
    IR21Profile,
)
from shared.schema import CanonicalDocument, SectionRecord, TableStructured


_TADIG_RE = re.compile(r"\b[A-Z]{5}\b")
_MCC_MNC_RE = re.compile(r"mnc(\d{2,3})\.mcc(\d{3})", re.I)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:/\d{1,2})?\b"
)
_FQDN_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?){1,}\b"
)


def is_ir21_document(doc: CanonicalDocument) -> bool:
    blob = " ".join(
        [
            doc.title or "",
            doc.file_name or "",
            " ".join(s.title for s in doc.sections[:8]),
        ]
    ).lower()
    return any(x in blob for x in ("ir.21", "ir 21", "ir21", "raex", "tadig", "lte roaming"))


def resolve_section_id(title: str, explicit: Optional[str] = None) -> Optional[str]:
    if explicit and str(explicit).strip().isdigit():
        return str(explicit).strip()
    t = re.sub(r"\s+", " ", (title or "").strip().lower())
    t = t.replace("ir. 21", "ir.21")
    if t in IR21_SECTION_MAP:
        return IR21_SECTION_MAP[t]
    for key, sid in IR21_SECTION_MAP.items():
        if key in t or t in key:
            return sid
    # e.g. "Section ID: 20" embedded
    m = re.search(r"section\s*id\s*[:#]?\s*(\d+)", t)
    if m:
        return m.group(1)
    return None


def extract_ir21_profile(doc: CanonicalDocument) -> Optional[IR21Profile]:
    if not is_ir21_document(doc):
        return None

    profile = IR21Profile(
        document_id=doc.document_id,
        file_name=doc.file_name,
        title=doc.title,
    )
    fields: list[IR21Field] = []
    endpoints: list[IR21Endpoint] = []

    for sec in doc.sections:
        sid = resolve_section_id(sec.title)
        # paragraphs as free-form fields when they look like key: value
        for para in sec.content or []:
            kv = _parse_kv_line(para)
            if kv:
                fields.append(
                    IR21Field(
                        field_key=kv[0],
                        field_value=kv[1],
                        section_id=sid,
                        section_title=sec.title,
                        page=sec.page_start,
                    )
                )
        for tbl in sec.tables or []:
            fields.extend(_fields_from_table(tbl, sec, sid))
            endpoints.extend(_endpoints_from_table(tbl, sec, sid))

    # Promote well-known fields
    for f in fields:
        key = f.field_key.lower().rstrip(":")
        val = f.field_value.strip()
        if not val or val.lower() in {"nan", "none", "null", "-"}:
            continue
        if "organisation name" in key or "organization name" in key:
            profile.organisation_name = profile.organisation_name or val
        elif "country" in key and len(val) <= 8:
            profile.country = profile.country or val
        elif "tadig" in key:
            m = _TADIG_RE.search(val.upper())
            if m and not profile.tadig:
                profile.tadig = m.group(0)
        elif "network type" in key:
            profile.network_type = profile.network_type or val
        elif "creation date" in key:
            profile.creation_date = profile.creation_date or val.split()[0]
        elif "effective date" in key:
            profile.effective_date = profile.effective_date or val.split()[0]

    # Infer TADIG / MCC / MNC from whole document text
    blob = _doc_blob(doc)
    if not profile.tadig:
        m = re.search(r"tadig[^A-Za-z0-9]{0,20}([A-Z]{5})\b", blob, re.I)
        if m:
            profile.tadig = m.group(1).upper()
        else:
            for cand in _TADIG_RE.findall(blob.upper()):
                if cand not in {"RAEX", "GSMA", "CCITT", "MSISDN", "SGSN", "GGSN", "MANDATORY"}:
                    profile.tadig = cand
                    break
    # Final sanitize
    if profile.tadig:
        m = _TADIG_RE.search(profile.tadig.upper())
        profile.tadig = m.group(0) if m else ""
    mm = _MCC_MNC_RE.search(blob)
    if mm:
        profile.mnc = mm.group(1)
        profile.mcc = mm.group(2)
    # Deduplicate fields
    seen: set[tuple[str, str, str]] = set()
    uniq: list[IR21Field] = []
    for f in fields:
        k = (f.field_key.lower(), f.field_value.lower(), f.section_id or "")
        if k in seen:
            continue
        if len(f.field_value) > 500:
            f.field_value = f.field_value[:500] + "…"
        if "dtype: str" in f.field_value or "Name:" in f.field_value and "dtype" in f.field_value:
            continue
        seen.add(k)
        # Clean common polluted IR.21 cell values
        f.field_value = _clean_field_value(f.field_key, f.field_value)
        if not f.field_value:
            continue
        uniq.append(f)
    profile.fields = uniq
    profile.endpoints = _dedupe_endpoints(endpoints)
    profile.metadata = {
        "section_count": len(doc.sections),
        "field_count": len(profile.fields),
        "endpoint_count": len(profile.endpoints),
    }
    return profile


def _clean_field_value(key: str, value: str) -> str:
    value = (value or "").strip()
    if not value or "dtype: str" in value:
        return ""
    kl = key.lower()
    if "tadig" in kl:
        m = _TADIG_RE.search(value.upper())
        return m.group(0) if m else value.split()[0][:5]
    if "date" in kl:
        m = re.search(r"\d{4}-\d{2}-\d{2}", value)
        return m.group(0) if m else value.split()[0]
    # Strip trailing "Section ID: N ..." pollution
    value = re.split(r"\bSection\s*ID\b", value, maxsplit=1)[0].strip(" :-")
    return value[:500]


def _doc_blob(doc: CanonicalDocument) -> str:
    parts = [doc.title, doc.file_name]
    for sec in doc.sections:
        parts.append(sec.title)
        parts.extend(sec.content or [])
        for tbl in sec.tables or []:
            parts.extend(tbl.headers or [])
            for row in tbl.rows or []:
                if isinstance(row, dict):
                    parts.extend(str(v) for v in row.values())
    return "\n".join(parts)


def _parse_kv_line(text: str) -> Optional[tuple[str, str]]:
    text = (text or "").strip()
    if not text or len(text) > 300:
        return None
    for sep in (":", "="):
        if sep in text:
            left, right = text.split(sep, 1)
            left, right = left.strip(), right.strip()
            if 2 <= len(left) <= 80 and right and len(right) <= 200:
                return left, right
    return None


def _fields_from_table(
    tbl: TableStructured,
    sec: SectionRecord,
    sid: Optional[str],
) -> list[IR21Field]:
    out: list[IR21Field] = []
    headers = [str(h).strip() for h in (tbl.headers or [])]
    rows = tbl.rows or []

    # 2-column key/value style (common in IR.21)
    if len(headers) == 2 and _looks_like_kv_headers(headers):
        # Sometimes header itself is a KV pair already
        if headers[0].endswith(":") or len(headers[0]) < 60:
            out.append(
                IR21Field(
                    field_key=headers[0].rstrip(":"),
                    field_value=headers[1],
                    section_id=sid,
                    section_title=sec.title,
                    page=tbl.page_number or sec.page_start,
                    table_id=tbl.table_id,
                )
            )
        for row in rows:
            items = list(row.items()) if isinstance(row, dict) else []
            if len(items) >= 2:
                k, v = str(items[0][1]).strip(), str(items[1][1]).strip()
                # dict keys may be the labels
                if isinstance(row, dict) and len(row) == 2:
                    keys = list(row.keys())
                    vals = list(row.values())
                    # Prefer key from header/label style
                    k = str(keys[0]).rstrip(":") if str(keys[0]).endswith(":") else str(vals[0])
                    v = str(vals[1]) if str(keys[0]).endswith(":") else str(vals[1])
                    # Standard: {label: value} where keys are labels
                    if all(not str(x).endswith(":") for x in keys):
                        # Could be {Creation date:, Creation time:} weird Docling output
                        k, v = str(keys[0]).rstrip(":"), str(vals[0])
                        out.append(
                            IR21Field(
                                field_key=k,
                                field_value=v,
                                section_id=sid,
                                section_title=sec.title,
                                page=tbl.page_number or sec.page_start,
                                table_id=tbl.table_id,
                            )
                        )
                        k2, v2 = str(keys[1]).rstrip(":"), str(vals[1])
                        out.append(
                            IR21Field(
                                field_key=k2,
                                field_value=v2,
                                section_id=sid,
                                section_title=sec.title,
                                page=tbl.page_number or sec.page_start,
                                table_id=tbl.table_id,
                            )
                        )
                        continue
                if k and v and k.lower() != v.lower():
                    out.append(
                        IR21Field(
                            field_key=k.rstrip(":"),
                            field_value=v,
                            section_id=sid,
                            section_title=sec.title,
                            page=tbl.page_number or sec.page_start,
                            table_id=tbl.table_id,
                        )
                    )
        return out

    # Wide tables: emit field as "Column=Value" per cell, plus row summary
    for row in rows:
        if not isinstance(row, dict):
            continue
        for k, v in row.items():
            ks, vs = str(k).strip(), str(v).strip()
            if not vs or vs.lower() in {"nan", "none", ""}:
                continue
            if ks.lower() == vs.lower():
                continue
            if len(ks) > 120 or len(vs) > 300:
                continue
            out.append(
                IR21Field(
                    field_key=ks.rstrip(":"),
                    field_value=vs,
                    section_id=sid,
                    section_title=sec.title,
                    page=tbl.page_number or sec.page_start,
                    table_id=tbl.table_id,
                )
            )
    return out


def _looks_like_kv_headers(headers: list[str]) -> bool:
    if len(headers) != 2:
        return False
    joined = " ".join(headers).lower()
    if any(x in joined for x in ("tadig", "organisation", "creation", "network type", "country")):
        return True
    return any(h.endswith(":") for h in headers) or max(len(h) for h in headers) < 40


def _endpoints_from_table(
    tbl: TableStructured,
    sec: SectionRecord,
    sid: Optional[str],
) -> list[IR21Endpoint]:
    out: list[IR21Endpoint] = []
    title = (sec.title or "").lower()
    headers_l = [str(h).lower() for h in (tbl.headers or [])]

    for row in tbl.rows or []:
        if not isinstance(row, dict):
            continue
        flat = {str(k).lower().strip(): str(v).strip() for k, v in row.items() if str(v).strip()}
        if not flat:
            continue

        ep = IR21Endpoint(section_id=sid, page=tbl.page_number or sec.page_start)

        # Network elements table
        if "node type" in flat or any("node type" in h for h in headers_l):
            ep.node_type = flat.get("node type", "")
            ep.role = ep.node_type
            ep.node_id = flat.get("node id", "")
            ep.gt_address = flat.get("gt address / address range", flat.get("gt address", ""))
            ep.ip = flat.get("ip address / address range", flat.get("ip address", ""))
            ep.vendor = flat.get("vendor info", flat.get("vendor", ""))
            if any([ep.node_type, ep.ip, ep.gt_address]):
                out.append(ep)
                continue

        # DEA / Diameter
        if any("dea" in h or "diameter" in h or "fqdn" in h for h in headers_l) or "lte" in title or "roaming interconnection" in title:
            for k, v in flat.items():
                if "fqdn" in k:
                    ep.fqdn = v
                elif "primary ip" in k or k.endswith("ip address dea fqdn") or "ip address" in k:
                    if not ep.ip:
                        ep.ip = v
                    else:
                        ep.ip_secondary = v
                elif "realm" in k:
                    ep.extras["realm"] = v
                    ep.fqdn = ep.fqdn or v
                elif "ipx" in k:
                    ep.extras["ipx_provider"] = v
                elif "architecture" in k:
                    ep.extras["architecture"] = v
            if ep.fqdn or ep.ip or ep.extras:
                ep.role = "DEA"
                ep.protocol = "Diameter"
                out.append(ep)
                continue

        # IP ranges
        if any("ip address range" in h or "ip address" in h for h in headers_l):
            for k, v in flat.items():
                if _IP_RE.search(v):
                    ep.ip = v
                    ep.role = "IP_RANGE" if "/" in v else "IP"
                    out.append(ep)
                    break

        # MMSC
        if any("mmsc" in h or "mms" in h for h in headers_l) or "mms" in title:
            ep.role = "MMSC"
            ep.protocol = "MMS"
            for k, v in flat.items():
                if "domain" in k or "fqdn" in k:
                    ep.fqdn = v
                elif "ip address" in k and "mta" not in k:
                    ep.ip = v
                elif "incoming mta" in k:
                    ep.extras["incoming_mta"] = v
                elif "outgoing mta" in k:
                    ep.extras["outgoing_mta"] = v
            if ep.fqdn or ep.ip:
                out.append(ep)

    return out


def _dedupe_endpoints(endpoints: list[IR21Endpoint]) -> list[IR21Endpoint]:
    seen: set[tuple[str, str, str]] = set()
    out: list[IR21Endpoint] = []
    for ep in endpoints:
        key = (ep.role, ep.ip, ep.fqdn)
        if key in seen:
            continue
        seen.add(key)
        out.append(ep)
    return out
