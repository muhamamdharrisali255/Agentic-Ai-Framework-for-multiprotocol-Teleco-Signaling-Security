"""Logical vector namespaces. IR.21 is never embedded.

One Qdrant/FAISS corpus, partitioned by `knowledge_kind` so the agent can
retrieve standards, tools, attack research, and policy separately.
"""

from __future__ import annotations

import re
from typing import Any

STANDARD = "standard"
TOOL = "tool"
ATTACK = "attack"
RESEARCH = "research"
POLICY = "policy"

KINDS = (STANDARD, TOOL, ATTACK, RESEARCH, POLICY)


def infer_knowledge_kind(file_name: str, *, source: str = "", document_type: str = "") -> str:
    fn = (file_name or "").lower()
    src = (source or "").lower()
    dtype = (document_type or "").lower()
    blob = f"{fn} {src} {dtype}"

    if any(k in blob for k in ("ir21", "ir.21", "raex")):
        return POLICY
    if any(k in blob for k in ("tshark", "t-shark", "wireshark", "suricata", "ids", "ips")):
        return TOOL
    if any(
        k in blob
        for k in (
            "attack", "threat", "hijack", "exploit", "ti-feed", "threatintel",
            "malware", "cve-", "advisory",
        )
    ):
        return ATTACK
    if any(k in blob for k in ("arxiv", "paper", "research", "journal", "survey")):
        return RESEARCH
    if any(k in blob for k in ("policy", "guideline", "fs.19", "fs19")):
        if "attack" in blob:
            return ATTACK
        return STANDARD if any(k in blob for k in ("fs.", "gsma", "3gpp", "etsi")) else POLICY
    if any(k in blob for k in ("3gpp", "gsma", "etsi", "ts33", "ts 33", "specification")):
        return STANDARD
    if "security" in blob:
        return STANDARD
    return STANDARD


def kinds_for_query(query: str, query_type: str, *, investigate: bool = False) -> list[str]:
    q = (query or "").lower()
    kinds: list[str] = []
    if any(k in q for k in ("tshark", "suricata", "wireshark", "signature", "detection rule", "ids", "ips")):
        kinds.append(TOOL)
    if any(k in q for k in ("attack", "hijack", "threat", "exploit", "malicious", "fraud", "abuse")):
        kinds.append(ATTACK)
    if any(k in q for k in ("paper", "research", "survey", "literature")):
        kinds.append(RESEARCH)
    if query_type in ("THREAT_ANALYSIS", "SECURITY_INVESTIGATION") or investigate:
        kinds.extend([ATTACK, STANDARD, TOOL])
    elif query_type in ("DOCUMENT_KNOWLEDGE", "MIXED", "SESSION_ANALYSIS"):
        kinds.append(STANDARD)
    if not kinds:
        kinds.append(STANDARD)
    # Preserve order, unique.
    seen: set[str] = set()
    out: list[str] = []
    for k in kinds:
        if k in KINDS and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def kind_of_evidence(item: dict[str, Any]) -> str:
    src = str(item.get("source") or item.get("file_name") or "")
    return infer_knowledge_kind(src)
