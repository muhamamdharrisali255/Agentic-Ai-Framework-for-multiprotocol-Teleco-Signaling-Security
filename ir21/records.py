"""Typed records for the RAEX IR.21 relational model.

IR.21 is a fixed GSMA template, so its content is genuinely relational: every
section carries typed records (network elements, MAP versions, number ranges)
rather than prose. These dataclasses mirror the PostgreSQL tables in
``ir21.postgres`` one-to-one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Document:
    document_id: str
    file_name: str
    tadig: str = ""
    organisation_name: str = ""
    country_initials: str = ""
    network_type: str = ""
    presentation_name: str = ""
    abbreviated_mnn: str = ""
    mcc: str = ""
    mnc: str = ""
    creation_date: str = ""
    creation_time: str = ""
    tadig_gen_schema: str = ""
    raex_schema: str = ""
    page_count: Optional[int] = None


@dataclass
class Section:
    section_id: str
    title: str
    obligation: str = ""
    effective_date: str = ""
    page: Optional[int] = None


@dataclass
class NetworkElement:
    node_type: str
    node_id: str = ""
    gt_address: str = ""
    ip_address: str = ""
    vendor: str = ""
    sw_hw_version: str = ""
    dual_access: str = ""
    location: str = ""
    utc_offset: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class MapVersion:
    application_context: str
    inbound_msc_vlr: str = ""
    inbound_sgsn: str = ""
    outbound: str = ""
    comments: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class CamelSupport:
    """CAP versions offered by gsmSSF/MSC per roaming direction."""

    node: str
    direction: str
    cap_versions: str
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class CamelService:
    service_name: str
    service_key: str = ""
    cap_version: str = ""
    scp_gt_addresses: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class CamelFeature:
    feature_group: str
    feature_name: str
    supported: str = ""
    planned_date: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class NumberRange:
    range_type: str
    cc: str = ""
    ndc: str = ""
    sn_start: str = ""
    sn_stop: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class DiameterEndpoint:
    fqdn: str = ""
    primary_ip: str = ""
    secondary_ip: str = ""
    ipx_provider: str = ""
    realm: str = ""
    architecture: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class RoamingFlag:
    """Boolean/enumerated interface capabilities (S6a, S8, SMS, scenarios)."""

    category: str
    attribute: str
    value: str
    counterpart: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class IpResource:
    kind: str
    value: str
    label: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class Apn:
    list_type: str
    apn: str
    username: str = ""
    password: str = ""
    gateway_ip: str = ""
    server_url: str = ""
    dns_primary: str = ""
    dns_secondary: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class Contact:
    category: str
    person_name: str = ""
    team_name: str = ""
    job_title: str = ""
    tel: str = ""
    mobile: str = ""
    fax: str = ""
    email: str = ""
    section_id: str = ""
    page: Optional[int] = None


@dataclass
class ChangeHistory:
    change_date: str
    section_id: str = ""
    section_name: str = ""
    description: str = ""
    page: Optional[int] = None


@dataclass
class UnusedSection:
    section_id: str
    section_name: str


@dataclass
class Fact:
    """Catch-all key/value so no documented value is lost to the typed tables."""

    field_key: str
    field_value: str
    section_id: str = ""
    section_title: str = ""
    page: Optional[int] = None


@dataclass
class Dataset:
    document: Document
    sections: list[Section] = field(default_factory=list)
    network_elements: list[NetworkElement] = field(default_factory=list)
    map_versions: list[MapVersion] = field(default_factory=list)
    camel_support: list[CamelSupport] = field(default_factory=list)
    camel_services: list[CamelService] = field(default_factory=list)
    camel_features: list[CamelFeature] = field(default_factory=list)
    number_ranges: list[NumberRange] = field(default_factory=list)
    diameter_endpoints: list[DiameterEndpoint] = field(default_factory=list)
    roaming_flags: list[RoamingFlag] = field(default_factory=list)
    ip_resources: list[IpResource] = field(default_factory=list)
    apns: list[Apn] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    change_history: list[ChangeHistory] = field(default_factory=list)
    unused_sections: list[UnusedSection] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "sections": len(self.sections),
            "network_elements": len(self.network_elements),
            "map_versions": len(self.map_versions),
            "camel_support": len(self.camel_support),
            "camel_services": len(self.camel_services),
            "camel_features": len(self.camel_features),
            "number_ranges": len(self.number_ranges),
            "diameter_endpoints": len(self.diameter_endpoints),
            "roaming_flags": len(self.roaming_flags),
            "ip_resources": len(self.ip_resources),
            "apns": len(self.apns),
            "contacts": len(self.contacts),
            "change_history": len(self.change_history),
            "unused_sections": len(self.unused_sections),
            "facts": len(self.facts),
        }
