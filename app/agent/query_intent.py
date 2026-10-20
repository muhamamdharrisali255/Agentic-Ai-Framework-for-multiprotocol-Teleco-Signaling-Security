"""Query intent — drives retrieval depth and answer format (generalized)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class QueryIntent(str, Enum):
    LOOKUP = "lookup"           # exact values, codes, which table row
    LIST = "list"               # enumerate items
    EXPLAIN = "explain"         # describe, how/why, compare, implications
    INVESTIGATE = "investigate"   # security / subscriber investigation
    PROCEDURE = "procedure"     # steps / validate / detect / filter
    GENERAL = "general"         # default document Q&A


class AnswerShape(str, Enum):
    """How the answer should be shaped — independent of domain content."""

    DEFINITION = "definition"
    ENUMERATION = "enumeration"
    PARAMETERS = "parameters"
    PROCEDURE = "procedure"
    COMPARISON = "comparison"
    INVESTIGATION = "investigation"
    GENERAL = "general"


@dataclass
class IntentProfile:
    intent: QueryIntent
    needs_synthesis: bool
    vector_top_k_multiplier: float
    refocus_search: bool
    prefer_structured_answer: bool
    answer_shape: AnswerShape = AnswerShape.GENERAL

    @property
    def skip_facts_fast(self) -> bool:
        return self.needs_synthesis or self.intent in (
            QueryIntent.EXPLAIN,
            QueryIntent.PROCEDURE,
        )


# Linguistic patterns only — no protocol or operator names
_LOOKUP_MARKERS = (
    "what is the", "what are the", "how many",
    "table row", "which row", "which table", "field value",
)
_LIST_MARKERS = (
    "list ", "list all", "enumerate", "show all", "name all",
    "which messages", "which message", "which commands", "which command",
    "which avps", "which avp", "which parameters", "what messages",
    "what commands", "types of messages", "types of commands",
    "messages are", "commands are", "associated with", "relevant to",
)
_EXPLAIN_MARKERS = (
    "explain", "describe", "how does", "how do", "why ",
    "differ", "difference", "detail", "mechanism",
    "affects", "affect", "implications", "what can",
)
_COMPARE_MARKERS = ("compare", " vs ", " versus ", "difference between", "inbound vs", "outbound vs")
_PROCEDURE_MARKERS = (
    "how to", "how should", "how would", "steps to", "step by step",
    "validate", "validation", "detect", "detection", "filter", "filtering",
    "checklist", "procedure", "algorithm", "pseudocode", "pseudo-code",
    "pseudo code", "implement", "workflow",
)
_PARAMETER_MARKERS = (
    "which parameters", "what parameters", "parameters should",
    "fields should", "which fields", "what fields", "avps should",
    "validation fields", "must check", "should check",
)
_INVESTIGATE_MARKERS = (
    "why was", "flagged", "suspicious", "investigate", "correlat",
    "malicious", "anomal", "detection", "potentially", "is this",
)
_DEFINITION_MARKERS = (
    r"\bwhat\s+is\b", r"\bwhat\s+are\b", r"\bdefine\b", r"\bdefinition\s+of\b",
    r"\bmeaning\s+of\b",
)
_SURICATA_RULE_MARKERS = re.compile(
    r"\b(suricata|ids)\s+rule\b|"
    r"\b(draft|create|write|generate|compose|build)\s+(a\s+)?(suricata|ids|detection)\s+rule\b|"
    r"\b(suricata|ids)\s+(signature|detection)\b",
    re.I,
)


def detect_answer_shape(query: str) -> AnswerShape:
    """Infer the presentation shape the user expects from the wording alone."""
    q = (query or "").lower().strip()
    if not q:
        return AnswerShape.GENERAL
    if any(m in q for m in _INVESTIGATE_MARKERS):
        return AnswerShape.INVESTIGATION
    if any(m in q for m in _COMPARE_MARKERS):
        return AnswerShape.COMPARISON
    if any(m in q for m in _PARAMETER_MARKERS):
        return AnswerShape.PARAMETERS
    if any(m in q for m in _PROCEDURE_MARKERS):
        return AnswerShape.PROCEDURE
    # Definition before enumeration so "What is a … message?" is not treated as a list.
    if any(re.search(p, q) for p in _DEFINITION_MARKERS) and not re.search(
        r"\b(which|list|enumerate|relevant|associated|types?\s+of)\b",
        q,
    ):
        return AnswerShape.DEFINITION
    if any(m in q for m in _LIST_MARKERS) or re.search(
        r"\b(which|what)\b.{0,60}\b(messages?|commands?|opcodes?|avps?|types?)\b",
        q,
    ):
        # "what is a Category-1 signaling message" already handled above.
        if re.search(r"\bwhat\s+is\b", q) and not re.search(
            r"\b(which|list|relevant|associated|types?\s+of)\b",
            q,
        ):
            return AnswerShape.DEFINITION
        return AnswerShape.ENUMERATION
    if any(m in q for m in _EXPLAIN_MARKERS):
        return AnswerShape.GENERAL
    if any(m in q for m in _LOOKUP_MARKERS) or q.startswith("what "):
        return AnswerShape.DEFINITION
    return AnswerShape.GENERAL


def is_suricata_rule_query(query: str) -> bool:
    """True when the user wants a Suricata rule drafted, not general Q&A."""
    return bool(_SURICATA_RULE_MARKERS.search(query or ""))


def format_suricata_rule_directive(query: str) -> str:
    """Presentation directive for Suricata rule drafting."""
    _ = query
    return (
        "Presentation: Suricata rule draft — sharp IDS-engineer voice, valid Suricata syntax.\n"
        "- ## Detection rule: one ```suricata``` fenced block with a complete one-line rule.\n"
        "  Format: action protocol src src_port -> dst dst_port (msg:\"...\"; sid:N; rev:1; ...)\n"
        "- Use drop for BLOCK, alert for ALERT. Include msg, sid, rev on every rule.\n"
        "- Match protocol header to evidence (tcp/3868 Diameter, udp/2123 GTP-C, sctp/3868, ip for SS7).\n"
        "- ## Checks: bullets mapping rule options to validation intent from evidence.\n"
        "- ## Action: state ALERT or BLOCK and whether the rule drops or alerts.\n"
        "- ## Notes: operational caveats only — NEVER cite PDFs, pages, or document names.\n"
        "- Never substitute pseudocode or prose for the Suricata rule line."
    )


def format_directive_for_query(query: str, shape: AnswerShape | None = None) -> str:
    """Short, generic instruction block telling the model how to present the answer."""
    if is_suricata_rule_query(query):
        return format_suricata_rule_directive(query)
    shape = shape or detect_answer_shape(query)
    common = (
        "Read the question carefully. Match the answer shape to the ask. "
        "Use only facts present in evidence — never invent fields, codes, or steps. "
        "Voice: principal interconnect security engineer — precise, confident, technical. "
        "NEVER mention sources, PDFs, pages, hashes, or “Source linkage”."
    )
    if shape == AnswerShape.ENUMERATION:
        return (
            f"{common}\n"
            "Presentation: This is an enumeration / “which …?” question.\n"
            "- ## Answer: 2–4 sharp sentences naming the set (e.g. Category-1 / prohibited "
            "on interconnect) and the governing operational rule.\n"
            "- ## Details: MUST be substantive — do not stop at a short summary.\n"
            "  Prefer a markdown table of every message/command/opcode named in evidence "
            "(columns such as Message / OpCode / Abbreviation / Notes / Action).\n"
            "  Then add a short operational rationale (why blocked / which category / "
            "bilateral-agreement caveat).\n"
            "  If evidence has multiple tables or annex lists, include all distinct items "
            "(dedupe names).\n"
            "- Do not answer with vague prose when names/codes appear in evidence.\n"
            "- If evidence is the wrong protocol, say so clearly and list nothing invented."
        )
    if shape == AnswerShape.PARAMETERS:
        return (
            f"{common}\n"
            "Presentation: This asks which parameters/fields to check.\n"
            "- Lead with a short operational answer naming the message/context.\n"
            "- In ## Details, use a markdown table: Parameter | Purpose / check | Direction "
            "(if present in evidence).\n"
            "- Group inbound vs outbound only when evidence separates them."
        )
    if shape == AnswerShape.PROCEDURE:
        return (
            f"{common}\n"
            "Presentation: This is a procedure / validation / detection how-to.\n"
            "- ## Answer: 1–3 sentence summary of the goal.\n"
            "- ## Details: numbered steps grounded in evidence (operational checks).\n"
            "- Then a ```pseudocode``` block that mirrors those steps "
            "(if/then checks, loops over fields) — only using checks present in evidence.\n"
            "- Optional small checklist table: Check | Why it matters."
        )
    if shape == AnswerShape.COMPARISON:
        return (
            f"{common}\n"
            "Presentation: This is a comparison.\n"
            "- Short contrast in ## Answer.\n"
            "- ## Details: markdown table with Aspect | Side A | Side B from evidence."
        )
    if shape == AnswerShape.DEFINITION:
        return (
            f"{common}\n"
            "Presentation: This is a definition / “what is …?” question.\n"
            "- ## Answer: precise definition in 2–4 sentences (include formal label if present).\n"
            "- ## Details: expand with criteria, examples, related categories, and a small "
            "table when evidence has one — do not leave Details nearly empty."
        )
    if shape == AnswerShape.INVESTIGATION:
        return (
            f"{common}\n"
            "Presentation: Investigation / threat style.\n"
            "- State the finding, then mechanism, then recommended checks.\n"
            "- Use a short table or numbered detection steps when evidence supports them."
        )
    return (
        f"{common}\n"
        "Presentation: Choose the clearest structure for the ask — "
        "definition, table, steps, or pseudocode when helpful and grounded."
    )


def analyze_intent(query: str, query_type: str = "") -> IntentProfile:
    q = (query or "").lower()
    shape = detect_answer_shape(query)

    # Preserve clear answer shapes (list / definition / procedure) even when the
    # upstream classifier tags THREAT_ANALYSIS — e.g. "list CAT-2 Diameter messages".
    _structured_shapes = (
        AnswerShape.ENUMERATION,
        AnswerShape.PARAMETERS,
        AnswerShape.DEFINITION,
        AnswerShape.PROCEDURE,
        AnswerShape.COMPARISON,
    )
    force_investigate = query_type in (
        "SECURITY_INVESTIGATION",
        "SUBSCRIBER_ANALYSIS",
        "SESSION_ANALYSIS",
        "THREAT_ANALYSIS",
        "MIXED",
    ) and shape not in _structured_shapes

    if force_investigate:
        intent = QueryIntent.INVESTIGATE
        shape = AnswerShape.INVESTIGATION
    elif any(m in q for m in _INVESTIGATE_MARKERS) and shape not in _structured_shapes:
        intent = QueryIntent.INVESTIGATE
    elif shape == AnswerShape.PROCEDURE or any(m in q for m in _PROCEDURE_MARKERS):
        intent = QueryIntent.PROCEDURE
    elif shape == AnswerShape.COMPARISON or any(m in q for m in _COMPARE_MARKERS):
        intent = QueryIntent.EXPLAIN
    elif shape == AnswerShape.ENUMERATION or shape == AnswerShape.PARAMETERS:
        intent = QueryIntent.LIST
    elif any(m in q for m in _EXPLAIN_MARKERS):
        intent = QueryIntent.EXPLAIN
    elif any(m in q for m in _LIST_MARKERS):
        intent = QueryIntent.LIST
    elif any(m in q for m in _LOOKUP_MARKERS) or q.strip().startswith("what "):
        intent = QueryIntent.LOOKUP
    else:
        intent = QueryIntent.GENERAL

    needs_synthesis = intent in (
        QueryIntent.EXPLAIN,
        QueryIntent.INVESTIGATE,
        QueryIntent.PROCEDURE,
        QueryIntent.LIST,
    )

    if intent == QueryIntent.LOOKUP:
        mult, refocus, prefer_structured = 3.0, True, True
    elif intent == QueryIntent.LIST:
        mult, refocus, prefer_structured = 2.5, True, True
    elif intent == QueryIntent.PROCEDURE:
        mult, refocus, prefer_structured = 3.0, True, True
    elif intent == QueryIntent.EXPLAIN:
        mult, refocus, prefer_structured = 3.0, False, False
    else:
        mult, refocus, prefer_structured = 2.0, False, intent == QueryIntent.LOOKUP

    return IntentProfile(
        intent=intent,
        needs_synthesis=needs_synthesis,
        vector_top_k_multiplier=mult,
        refocus_search=refocus,
        prefer_structured_answer=prefer_structured,
        answer_shape=shape,
    )


def build_refocus_query(original: str, enhanced: str) -> str:
    """Second-pass retrieval query from user terms (no domain hardcoding)."""
    base = enhanced or original
    tokens = [t for t in re.split(r"\W+", original or "") if len(t) >= 4]
    extra = " ".join(list(dict.fromkeys(tokens))[:10])
    if extra and extra.lower() not in base.lower():
        return f"{base} {extra}".strip()
    return base


def select_answer_style(
    intent: QueryIntent,
    evidence: list[dict[str, Any]],
) -> str:
    """Default structured professional brief for all general Q&A."""
    _ = intent, evidence  # reserved for future specialist routing
    return "professional"


def filter_evidence_by_scope(
    evidence: list[dict[str, Any]],
    filters: dict[str, Any],
) -> list[dict[str, Any]]:
    """Drop document hits that do not match scoped file_name."""
    fn = filters.get("file_name")
    if not fn:
        return evidence
    names = filters.get("file_names") or []
    allowed = {fn, *names}
    out = []
    for e in evidence:
        if e.get("type") != "Document":
            out.append(e)
            continue
        src = str(e.get("source") or "")
        if any(a in src for a in allowed):
            out.append(e)
    return out
