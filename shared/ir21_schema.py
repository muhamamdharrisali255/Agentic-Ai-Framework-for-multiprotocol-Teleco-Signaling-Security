"""Typed IR.21 / RAEX structured schema for hybrid RAG."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# Common RAEX IR.21 section title → Section ID
IR21_SECTION_MAP: dict[str, str] = {
    "organisation information": "1",
    "organization information": "1",
    "network": "2",
    "network information": "3",
    "routing information": "4",
    "international sccp gateway": "5",
    "domestic sccp gateway": "6",
    "subscriber identity authentication": "7",
    "mobile application part (map)": "8",
    "mobile application part": "8",
    "map": "8",
    "network elements information": "9",
    "network elements": "9",
    "camel info": "10",
    "camel": "10",
    "packet data services": "11",
    "gprs": "11",
    "wlan": "12",
    "lte information": "19",
    "lte roaming information": "20",
    "lte roaming": "20",
    "roaming interconnection": "20",
    "ip - roaming and ip - interworking information": "17",
    "ip roaming": "17",
    "ip - roaming": "17",
    "mms interworking information": "18",
    "mms": "18",
    "contact information": "21",
    "history of changes": "0",
    "raex ir. 21 information": "0",
    "gsma roaming database ir. 21 data": "0",
}


class IR21Field(BaseModel):
    field_key: str
    field_value: str
    section_id: Optional[str] = None
    section_title: str = ""
    page: Optional[int] = None
    table_id: Optional[str] = None
    source_chunk_id: Optional[str] = None
    confidence: float = 1.0


class IR21Endpoint(BaseModel):
    role: str = ""  # DEA, HLR, HSS, PGW, MMSC, SCCP, ...
    node_type: str = ""
    node_id: str = ""
    fqdn: str = ""
    ip: str = ""
    ip_secondary: str = ""
    port: str = ""
    protocol: str = ""
    gt_address: str = ""
    vendor: str = ""
    section_id: Optional[str] = None
    page: Optional[int] = None
    extras: dict[str, str] = Field(default_factory=dict)


class IR21Profile(BaseModel):
    """Normalized IR.21 document profile."""

    document_id: str
    file_name: str
    title: str = ""
    organisation_name: str = ""
    country: str = ""
    tadig: str = ""
    network_type: str = ""
    creation_date: str = ""
    effective_date: str = ""
    mcc: str = ""
    mnc: str = ""
    fields: list[IR21Field] = Field(default_factory=list)
    endpoints: list[IR21Endpoint] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_facts_markdown(self, limit: int = 80) -> str:
        lines = [
            f"### IR.21 Structured Profile — {self.file_name}",
            f"- **Organisation**: {self.organisation_name or 'n/a'}",
            f"- **Country**: {self.country or 'n/a'}",
            f"- **TADIG**: {self.tadig or 'n/a'}",
            f"- **MCC/MNC**: {self.mcc or '?'}/{self.mnc or '?'}",
            f"- **Network type**: {self.network_type or 'n/a'}",
            f"- **Creation date**: {self.creation_date or 'n/a'}",
            f"- **Effective date**: {self.effective_date or 'n/a'}",
            "",
            "#### Key fields",
        ]
        for f in self.fields[:limit]:
            sec = f" [Sec {f.section_id}]" if f.section_id else ""
            page = f" (p.{f.page})" if f.page else ""
            lines.append(f"- **{f.field_key}**{sec}{page}: {f.field_value}")
        if self.endpoints:
            lines.append("")
            lines.append("#### Endpoints / network elements")
            for ep in self.endpoints[:40]:
                bits = [x for x in [ep.role or ep.node_type, ep.fqdn, ep.ip, ep.gt_address, ep.protocol] if x]
                lines.append(f"- {' | '.join(bits)}")
        return "\n".join(lines)


class RelationRecord(BaseModel):
    subject: str
    subject_type: str
    predicate: str
    object: str
    object_type: str
    document_id: str
    file_name: str = ""
    section_id: Optional[str] = None
    page: Optional[int] = None
    source_text: str = ""
    confidence: float = 1.0
