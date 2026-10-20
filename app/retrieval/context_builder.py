"""Evidence context builder + reranker (implementation_plan.md §23–25)."""

from __future__ import annotations

import re
from typing import Any

from app.config.settings import settings
from app.retrieval.query_terms import (
    hard_terms,
    intent_alignment_score,
    key_identifiers,
    query_tokens,
)

# Higher tier = stronger boost in reranking (generalized, not domain-specific)
_TYPE_TIER: dict[str, float] = {
    "Structured Facts": 3.5,
    "Message Policy": 3.45,
    "Graph Fact": 3.4,
    "Table": 3.2,
    "IDS": 3.0,
    "Threat Knowledge": 2.8,
    "Tool Knowledge": 2.6,
    "Structured Database": 2.5,
    "Structured Record": 2.5,
    "Network Event": 2.2,
    "Domain Dictionary": 1.8,
    "Document": 0.0,
}

_NOISE_MARKERS = (
    "table of contents",
    "security classification:",
    "copyright notice",
    "whitelisting table",
)


def rerank(
    results: list[dict[str, Any]],
    query: str,
    top_k: int | None = None,
    *,
    candidate_scores: dict[str, float] | None = None,
    scoped_files: list[str] | None = None,
    prefer_synthesis: bool = False,
    taxonomy_facets: Any | None = None,
) -> list[dict[str, Any]]:
    """Boost structured evidence and scoped documents; demote noise."""
    k = top_k or settings.rerank_top_k
    if not results:
        return []
    qtoks = query_tokens(query)
    keys = key_identifiers(query)
    hard = hard_terms(query) | keys
    scoped = [f.lower() for f in (scoped_files or [])]

    def score(item: dict[str, Any]) -> float:
        etype = item.get("type") or "Document"
        base = float(item.get("score", 0.0)) + _TYPE_TIER.get(etype, 0.0)
        text = (item.get("body") or item.get("text") or "").lower()
        section = (item.get("section") or "").lower()
        source = (item.get("source") or "").lower()

        if candidate_scores:
            for fn, boost in candidate_scores.items():
                if fn.lower() in source:
                    base += min(boost * 0.12, 3.5)
                    break
        elif scoped:
            if any(sf in source for sf in scoped):
                base += 2.0
            elif etype == "Document" and scoped:
                base -= 2.0

        if any(m in text for m in _NOISE_MARKERS):
            base -= 1.5
        if "abbreviations" in section or section.endswith("references"):
            base -= 1.0
        if section and any(t in section for t in hard):
            base += 2.5
        if keys and any(k in text for k in keys):
            base += 2.0
        if "history of changes" in text and not any(t in text for t in hard):
            base -= 2.0

        hard_hits = sum(1 for t in hard if t in text or t in section)
        if hard:
            base += hard_hits * 0.9
            # Soft demote only — never exclude loosely related FS prose.
            if hard_hits == 0 and etype in ("Structured Facts", "Document"):
                base -= 1.0
            if hard_hits == 0 and any(
                n in text
                for n in ("contact information", "abbreviated mnn", "country initials", "jobtitle")
            ):
                base -= 3.5

        # Soft intent alignment from query/taxonomy expansions.
        base += intent_alignment_score(f"{text} {section} {source}", query)

        if prefer_synthesis:
            if etype in ("Document", "Threat Knowledge", "Message Policy", "IDS"):
                base += 1.2
            elif etype == "Table":
                base -= 0.3
            if etype == "Structured Facts" and item.get("agent") == "ir21":
                base -= 1.5

        qlow = (query or "").lower()
        if re.search(r"\bparameters?\b", qlow) and re.search(r"\bvalidat", qlow):
            if etype == "Message Policy":
                base += 4.0
            if etype == "Table":
                base += 2.5
            if etype == "Document":
                base += 1.5
        if re.search(r"\bwhich\b", qlow) and re.search(r"\bmessages?\b", qlow):
            if etype == "Document":
                base += 2.0
            if etype == "Message Policy":
                base += 2.5
            if etype == "Domain Dictionary":
                base -= 0.5
        if re.search(r"\b(what\s+is|define|definition)\b", qlow):
            if etype == "Domain Dictionary":
                base += 5.0
            section_l = section.lower()
            if re.search(r"7\.2|interface-unauthorised|home-network|plausible-network", section_l + " " + text[:200]):
                base += 4.0
            if "implement diameter firewall" in text or "table of contents" in section_l:
                base -= 4.0
        if re.search(r"\bdifference\b", qlow) and etype == "Domain Dictionary":
            base += 2.0
        if taxonomy_facets is not None:
            base += taxonomy_facets.match_score(item)
        elif prefer_synthesis and etype == "Message Policy" and re.search(
            r"\b(which|parameters?|messages?|protocol)\b", qlow
        ):
            base += 0.5

        base += sum(0.08 for t in qtoks if t in text or t in section)
        return base

    return sorted(results, key=score, reverse=True)[:k]


def build_context(evidence: list[dict[str, Any]]) -> str:
    if not evidence:
        return "No evidence retrieved."
    try:
        from app.retrieval.context_expand import expand_evidence_list

        # Already expanded in pure_qdrant_search; expand again is cheap/deduped
        # when payloads lack neighbor links (no-op growth).
        if not any(ev.get("expansion_role") for ev in evidence):
            evidence = expand_evidence_list(evidence)
    except Exception:
        pass
    ordered = _order_for_generation(evidence)
    blocks = []
    for i, ev in enumerate(ordered, 1):
        etype = ev.get("type", "unknown")
        source = ev.get("source", "")
        chunk_id = ev.get("chunk_id") or ""
        body = ev.get("body", "")
        try:
            score = float(ev.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        id_line = f"chunk_id: {chunk_id}\n" if chunk_id else ""
        role = ev.get("expansion_role")
        role_line = f"Role: {role}\n" if role and role != "match" else ""
        toc = ev.get("toc_path") or ""
        toc_line = f"Section path: {toc}\n" if toc else ""
        blocks.append(
            f"SOURCE {i} (relevance={score:.3f}):\n"
            f"Type: {etype}\nSource: {source}\n{id_line}{role_line}{toc_line}"
            f"Evidence:\n{body}"
        )
    context = "\n\n".join(blocks)
    max_chars = int(getattr(__import__("config"), "MAX_RETRIEVAL_CONTEXT_CHARS", 48000) or 48000)
    if len(context) > max_chars:
        context = context[:max_chars] + "\n\n[context truncated]"
    return context


def _order_for_generation(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep highest-ranked evidence first so CONTEXT 1 matches retrieval order.

    Cross-encoder scores are often negative; sort numerically descending so the
    best (largest) score leads. Avoid lost-in-the-middle interleaving — it buries
    the top hit for smaller RAG generators.
    """
    return sorted(evidence, key=lambda x: float(x.get("score") or 0), reverse=True)


def evidence_from_tool_result(
    tool_name: str,
    payload: dict[str, Any],
    *,
    label: str = "",
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    results = payload.get("results") or []
    for r in results:
        if tool_name == "vector_search":
            meta = r.get("metadata") or {}
            body = r.get("text", "")
            source = meta.get("file_name") or meta.get("document_title") or "vector"
            page = meta.get("page")
            if page:
                source += f" p.{page}"
            out.append({
                "type": "Document",
                "source": source,
                "body": body,
                "score": r.get("score", 0),
                "chunk_id": r.get("chunk_id") or meta.get("chunk_id"),
                "section": meta.get("section", ""),
                "toc_path": " > ".join(meta.get("heading_path") or []) or meta.get("section", ""),
            })
        elif tool_name in ("threat_search", "find_attack_pattern"):
            if r.get("body"):
                out.append({
                    "type": "Threat Knowledge",
                    "source": r.get("source", ""),
                    "body": r.get("body", ""),
                    "score": r.get("score", 2.0),
                    "section": r.get("section", ""),
                    "chunk_id": r.get("chunk_id"),
                })
                continue
            indicators = r.get("indicators", [])
            if isinstance(indicators, str):
                indicators = [indicators]
            body = (
                f"Attack ID: {r.get('attack_id', '')}\n"
                f"Name: {r.get('name', '')}\n"
                f"Protocol: {r.get('protocol', '')}\n"
                f"Severity: {r.get('severity', '')}\n"
                f"Description: {r.get('description', '')}\n"
                f"Indicators: {indicators}"
            )
            out.append({"type": "Threat Knowledge", "source": r.get("attack_id", ""), "body": body, "score": 2.0})
        elif tool_name == "tool_knowledge_search":
            out.append({
                "type": "Tool Knowledge",
                "source": r.get("source", "tool knowledge"),
                "body": r.get("body") or r.get("text") or str(r),
                "score": r.get("score", 1.6),
                "section": r.get("section", ""),
                "chunk_id": r.get("chunk_id"),
            })
        elif tool_name == "find_alerts":
            body = f"Alert {r.get('alert_code')} severity={r.get('severity')} protocol={r.get('protocol')} — {r.get('description', '')}"
            out.append({"type": "IDS", "source": r.get("alert_code", ""), "body": body, "score": 2.5})
        elif tool_name == "find_sessions":
            body = f"Session {r.get('session_code')} protocol={r.get('protocol')} src={r.get('source_ip')} dst={r.get('destination_ip')}"
            out.append({"type": "Structured Database", "source": "sessions", "body": body, "score": 1.5})
        elif tool_name == "find_subscriber":
            body = f"Subscriber {r.get('subscriber_code')} IMSI={r.get('imsi')} MSISDN={r.get('msisdn')}"
            out.append({"type": "Structured Database", "source": "subscribers", "body": body, "score": 1.8})
        elif tool_name == "dictionary_search":
            body = f"{r.get('term')}: {r.get('definition', '')}"
            out.append({"type": "Domain Dictionary", "source": r.get("term", ""), "body": body})
        elif tool_name == "find_operator":
            body = f"Operator {r.get('name')} TADIG={r.get('tadig')} MCC/MNC={r.get('mcc')}/{r.get('mnc')}"
            out.append({"type": "Structured Database", "source": "operators", "body": body})
        elif tool_name == "table_search":
            field = r.get("Field") or r.get("Role") or "Row"
            value = r.get("Value") or r.get("GT") or ""
            section = r.get("Section") or ""
            src = r.get("Source") or f"{r.get('_document_id', 'table')} p.{r.get('_page', '—')}"
            body = (
                f"Structured table row\n"
                f"Field: {field}\n"
                f"Value: {value}\n"
                f"Section: {section}\n"
                f"Source: {src}"
            )
            out.append({
                "type": "Table",
                "source": src,
                "body": body,
                "score": 3.0,
                "section": section,
            })
        elif tool_name == "event_search":
            body = (
                f"Event {r.get('event_id')} {r.get('event_type')} "
                f"protocol={r.get('protocol')} severity={r.get('severity')}"
            )
            out.append({"type": "Network Event", "source": r.get("event_id", ""), "body": body, "score": 2.0})
        elif tool_name == "structured_facts":
            text = r.get("text") or payload.get("text") or ""
            sources = r.get("sources") or []
            src = ", ".join(sources[:3]) if sources else "structured_facts"
            out.append({"type": "Structured Facts", "source": src, "body": text, "score": 2.4})
        else:
            out.append({"type": tool_name, "source": label or tool_name, "body": str(r)})
    return out
