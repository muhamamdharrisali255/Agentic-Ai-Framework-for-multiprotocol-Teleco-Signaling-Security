"""Extensible specialist capability registry.

New knowledge sources are added here as capability cards. The Master scores the
user question against these descriptions — there is no hardcoded question→store map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SpecialistCapability:
    """One specialist = one knowledge store + what it is good for."""

    agent: str
    store: str
    description: str
    wave: str = "cpu"  # cpu | vector | post
    kind: str | None = None  # vector knowledge_kind when wave=vector
    baseline: float = 0.0  # always-on bias (dictionary)
    parallel: bool = True


# Register specialists here to extend the system — Master discovers them dynamically.
SPECIALIST_CAPABILITIES: tuple[SpecialistCapability, ...] = (
    SpecialistCapability(
        agent="dictionary",
        store="domain_dictionary",
        wave="cpu",
        baseline=0.55,
        description=(
            "Domain dictionary and taxonomy: abbreviations, term definitions, "
            "protocol names, category labels (CAT1 CAT2 CAT3), message aliases, "
            "what a term means in telecom signalling security."
        ),
    ),
    SpecialistCapability(
        agent="ir21",
        store="ir21_postgresql",
        wave="cpu",
        description=(
            "GSMA RAEX IR.21 operator structured records: TADIG, operator name, "
            "CAP versions, global titles, GT lists, node addresses, LTE roaming "
            "interface flags (S6a S8), contacts, supported values per operator. "
            "Exact configuration lookups from enrolled IR.21 documents."
        ),
    ),
    SpecialistCapability(
        agent="graph",
        store="neo4j_ontology",
        wave="cpu",
        description=(
            "Ontology graph of roaming identity relationships: is a GT global title or "
            "Diameter host/realm authorized for an operator; operator authorization checks; "
            "roaming partner agreement status; network element identity binding; whether a "
            "ULR or AIR message sequence is legitimate for a subscriber; FOLLOWED_BY "
            "transitions between signalling messages; subscriber registration and session "
            "state. Not for generic attack definitions or Suricata signature text."
        ),
    ),
    SpecialistCapability(
        agent="policy",
        store="message_policy",
        wave="cpu",
        description=(
            "Signalling firewall message policy table: Category-1 prohibited interconnect "
            "messages, Category-2 inbound roaming partner validation, Category-3.1 flow-sequence "
            "abuse, Category-3.2 context plausibility; parameters to validate for UpdateLocation, "
            "Diameter Update-Location-Request ULR, Authentication-Information-Request AIR, "
            "GTP-C Create Session Request; Origin-Host Origin-Realm VPLMN IMSI MCC MNC; "
            "Command-Code Application-ID; ALERT or BLOCK actions."
        ),
    ),
    SpecialistCapability(
        agent="ips_events",
        store="network_events",
        wave="cpu",
        description=(
            "Observed live or captured signalling traffic and runtime context: IPS alerts, "
            "signaling events, recent ULR AIR SAI CreateSession messages on the wire, "
            "IMSI activity, source and destination addresses, whether a sequence of events "
            "was seen; answers questions about what happened in the network just now."
        ),
    ),
    SpecialistCapability(
        agent="standards",
        store="vector:standard",
        wave="vector",
        kind="standard",
        parallel=False,
        description=(
            "Standards and specifications corpus: GSMA FS.19 Diameter Interconnect Security, "
            "3GPP and ETSI signalling security guidance, recommended interconnect controls, "
            "explanations of mechanisms, comparisons between categories, why MCC/MNC alone is "
            "not enough, how authentication and location management messages work."
        ),
    ),
    SpecialistCapability(
        agent="tools",
        store="vector:tool",
        wave="vector",
        kind="tool",
        parallel=False,
        description=(
            "IDS and IPS tooling knowledge: Suricata rules and signatures, Wireshark and tshark "
            "dissection, how to monitor and alert on signalling, enrolled tool rule text."
        ),
    ),
    SpecialistCapability(
        agent="attack",
        store="vector:attack",
        wave="vector",
        kind="attack",
        parallel=False,
        description=(
            "Attack and threat intelligence: GTP session hijack, authentication vector probing, "
            "location update abuse, cross-protocol roaming fraud, TI feeds, indicators of "
            "compromise, how signalling attacks work."
        ),
    ),
    SpecialistCapability(
        agent="research",
        store="vector:research",
        wave="vector",
        kind="research",
        parallel=False,
        description=(
            "Academic papers, surveys, and research literature on telecom signalling security."
        ),
    ),
    SpecialistCapability(
        agent="ids_rules",
        store="detection_rule+vector",
        wave="post",
        parallel=False,
        description=(
            "Enrolled detection rules and Suricata IDS signatures from the detection_rule store: "
            "quote or compose grounded rules for unauthorized inbound Diameter ULR, SAI probing, "
            "GTP Create Session without context, APN routing violations; attack_pattern linkage; "
            "never invent unpublished signature IDs."
        ),
    ),
)


def capability_by_agent() -> dict[str, SpecialistCapability]:
    return {c.agent: c for c in SPECIALIST_CAPABILITIES}


def register_specialist(cap: SpecialistCapability) -> None:
    """Runtime extension hook — append a new specialist without changing routing code."""
    global SPECIALIST_CAPABILITIES
    existing = capability_by_agent()
    if cap.agent in existing:
        SPECIALIST_CAPABILITIES = tuple(
            cap if c.agent == cap.agent else c for c in SPECIALIST_CAPABILITIES
        )
    else:
        SPECIALIST_CAPABILITIES = SPECIALIST_CAPABILITIES + (cap,)
    try:
        from app.agent.dynamic_planner import _capability_embeddings

        _capability_embeddings.cache_clear()
    except Exception:
        pass


def registry_as_prompt() -> str:
    """Human/LLM-readable catalogue of available specialists."""
    lines = []
    for c in SPECIALIST_CAPABILITIES:
        lines.append(f"- {c.agent} [{c.store}]: {c.description}")
    return "\n".join(lines)
