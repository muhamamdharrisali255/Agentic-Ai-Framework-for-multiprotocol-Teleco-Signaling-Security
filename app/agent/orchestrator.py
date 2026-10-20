"""Agent orchestrator — Observe → Understand → Plan → Retrieve → Evaluate → Reason."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from app.agent.classifier import classify_query, extract_entities
from app.agent.evidence_chunks import evidence_to_chunks
from app.agent.intelligence import assess
from app.agent.master import assign_tasks, collect_reports, reports_markdown
from app.agent.parser import parse_agent_context
from app.agent.planner import build_plan
from app.agent.report import merge_evidence
from app.agent.specialists import SpecialistContext
from app.agent.state import AgentState
from app.agent.query_scope import infer_scope
from app.agent.query_intent import (
    analyze_intent,
    select_answer_style,
)
from app.agent.knowledge_domains import KnowledgeDomain, classify_knowledge_domain
from app.agent.pipeline import (
    PipelineMode,
    classify_pipeline_mode,
    stage_evaluate,
    stage_observe,
    stage_plan,
    stage_retrieve,
    stage_understand,
)
from app.agent.taxonomy_classifier import is_policy_instruction
from app.agent.router import HYBRID, STRUCTURED, choose_route
from app.config.settings import settings
from app.nlp.query_enhancer import get_query_enhancer
from app.retrieval.candidate_selector import get_candidate_selector
from app.retrieval.context_builder import build_context, rerank


def run_agent(
    query: str,
    *,
    top_k: int | None = None,
    document: str | None = None,
    skip_facts_fast: bool = False,
    history: list[dict[str, str]] | None = None,
    observation: dict[str, Any] | None = None,
) -> AgentState:
    t0 = time.perf_counter()
    state = AgentState(user_query=query, trace_id=str(uuid.uuid4())[:12])
    k = top_k or settings.retrieval_top_k

    # 1. OBSERVE — IPS / IDS incident → Agent Context (never raw packets to the LLM).
    observe = stage_observe(query, observation)
    agent_ctx = parse_agent_context(query, observe.agent_context)
    state.detection_rules = list(observe.detection_rules)
    state.tools_used.extend(observe.tools_used)
    state.agent_context = observe.agent_context
    state.pipeline_mode = observe.pipeline_mode.value
    state.ids_verification = dict(observe.ids_verification or {})
    state.stages.append("observe")

    # 2. UNDERSTAND — dictionary + intent + entities.
    understand = stage_understand(query, state.agent_context, document=document)
    entities = understand.entities
    scope = understand.scope
    state.enhanced_query = understand.enhanced_query
    state.expanded_terms = understand.expanded_terms
    state.entities = entities
    state.query_type = understand.query_type
    state.candidate_sources = understand.candidate_sources
    state.candidate_filter = understand.candidate_filter
    intent = analyze_intent(query, state.query_type)
    state.stages.append("understand")

    if not state.pipeline_mode:
        state.pipeline_mode = classify_pipeline_mode(
            query, observation=observation, agent_ctx=agent_ctx
        ).value

    state.agent_context = {
        **state.agent_context,
        "_scope": scope,
        "_document": document,
        "_taxonomy": understand.taxonomy.as_dict(),
        "_pipeline_mode": state.pipeline_mode,
    }

    if state.pipeline_mode == PipelineMode.CASE3_POLICY_RULE.value or is_policy_instruction(query):
        from app.agent.policy_resolver import resolve_policy
        from app.agent.attack_history import classify_attack_from_history, is_new_attack_query

        policy_bundle = resolve_policy(query)
        attack_class = classify_attack_from_history(
            query,
            history=history,
            observation=observation or state.agent_context,
        )
        policy_bundle["attack_classification"] = attack_class
        # Step 0 SQL rows are CONTEXT TO SYNTHESIZE — never user-facing raw dumps.
        syn = _synthesize_policy_context(policy_bundle)
        if attack_class.get("explanation"):
            syn["synthesis_brief"] = (
                f"[Attack classification]\n{attack_class['explanation']}\n\n"
                + (syn.get("synthesis_brief") or "")
            )
        state.agent_context = {
            **state.agent_context,
            "_policy_resolution": syn,
            "_attack_classification": attack_class,
            "_pipeline_mode": PipelineMode.CASE3_POLICY_RULE.value,
            "_new_attack": is_new_attack_query(query),
        }
        state.pipeline_mode = PipelineMode.CASE3_POLICY_RULE.value
        if policy_bundle.get("detection_rules"):
            state.detection_rules = list(policy_bundle["detection_rules"])

    # 3. PLAN
    plan_result = stage_plan(
        query,
        understand,
        state.agent_context,
        history=history,
        top_k=k,
        pipeline_mode=state.pipeline_mode,
    )
    state.route = plan_result.route
    knowledge_domain = plan_result.knowledge_domain
    state.plan = plan_result.plan
    state.specialists = plan_result.specialists
    state.knowledge_kinds = plan_result.knowledge_kinds
    state.candidate_sources = plan_result.candidate_sources
    state.agent_context = {
        **state.agent_context,
        "_knowledge_domain": knowledge_domain.value,
    }
    state.stages.append("plan")

    if scope.get("file_name") and not document:
        document = scope["file_name"]
    if document:
        plan_result.filters["file_name"] = document

    # 4. RETRIEVE
    retrieve = stage_retrieve(
        query,
        plan_result,
        understand,
        state.agent_context,
        expanded_terms=state.expanded_terms,
        existing_detection_rules=state.detection_rules,
        existing_tools=state.tools_used,
    )
    state.reports = [r.as_dict() for r in retrieve.reports]
    state.tools_used = retrieve.tools_used
    state.round1_documents = retrieve.round1_documents
    state.detection_rules = retrieve.detection_rules or state.detection_rules
    state.structured_results = retrieve.structured_results
    state.replanned = retrieve.replanned
    if state.replanned:
        state.stages.append("replan")
    state.stages.append("retrieve")

    for report in retrieve.reports:
        if report.agent == "ir21":
            state.sql_queries.extend(report.meta.get("queries") or [])

    # 5. EVALUATE
    evaluated = stage_evaluate(
        query,
        retrieve,
        plan_result,
        state.agent_context,
        intent_needs_synthesis=intent.needs_synthesis,
        taxonomy=understand.taxonomy,
        expanded_terms=understand.expanded_terms,
    )
    state.evidence = evaluated.evidence
    state.structured_results = evaluated.structured_results
    state.final_context = evaluated.final_context
    if evaluated.detection_rules:
        state.detection_rules = evaluated.detection_rules
    state.stages.append("evaluate")

    has_policy_or_ids = any(
        e.get("type") in ("Message Policy", "IDS") or e.get("agent") in ("policy", "ids_rules")
        for e in state.structured_results
    )
    ir21_led = _ir21_identity_led(query, state.route, state.structured_results)

    # 6. CORRELATE — fuse specialist reports into a security finding.
    state.finding = assess(
        query,
        agent_ctx,
        state.evidence,
        query_type=state.query_type,
        route=state.route.route if state.route else "",
        detection_rules=state.detection_rules,
    )
    state.stages.append("correlate")

    if not state.evidence:
        state.answer = "Insufficient evidence."
        state.confidence = "INSUFFICIENT"
    else:
        state.confidence = state.finding.get("confidence") or _estimate_confidence(state)
        answer_style = select_answer_style(intent.intent, state.evidence)
        qlow = (query or "").lower()
        wants_rule = any(
            k in qlow
            for k in (
                "detection rule",
                "create a rule",
                "draft a rule",
                "suricata rule",
                "ids rule",
                "block all",
                "enforce",
            )
        )
        case_mode = state.pipeline_mode or ""
        if case_mode == PipelineMode.CASE3_POLICY_RULE.value:
            # Case 3 always drafts with resolved attack/detection scope + Qdrant support.
            answer_style = "rule_draft"
        elif wants_rule:
            answer_style = "rule_draft"
        # Case 2 chatbot: never attach SQL detection_rule rows (unless drafting Suricata).
        if case_mode == PipelineMode.CASE2_RAG_CHAT.value and answer_style != "rule_draft":
            state.detection_rules = []
        elif case_mode != PipelineMode.CASE2_RAG_CHAT.value and state.detection_rules:
            from app.agent.rule_composer import should_use_rule_draft

            if should_use_rule_draft(state.detection_rules, agent_ctx):
                answer_style = "rule_draft"
        elif state.query_type == "SECURITY_INVESTIGATION" or agent_ctx.has_observation:
            answer_style = "security_intelligence"
        elif state.structured_results and state.route is not None:
            if state.route.route == STRUCTURED or ir21_led:
                answer_style = "record_lookup"
            elif state.route.route == HYBRID:
                answer_style = "hybrid"

        gen_context = state.final_context
        if case_mode == PipelineMode.CASE3_POLICY_RULE.value:
            # Case 3: SQL resolve_policy rows → synthesis context; Qdrant for standards support.
            # Pass cleaned detection_rules into the generator for drafting (not Case 2).
            gen_rules = _case3_rules_for_draft(state.detection_rules)
            pol_ctx = (state.agent_context or {}).get("_policy_resolution") or {}
            brief = pol_ctx.get("synthesis_brief") if isinstance(pol_ctx, dict) else None
            if brief:
                gen_context = (
                    "[Case 3 policy scope — attack patterns & detection intents to draft against]\n"
                    f"{brief}\n\n"
                    "[Qdrant standards / Suricata corpus — ground the draft here]\n"
                    f"{gen_context}"
                )
            state.detection_rules = gen_rules
        elif case_mode == PipelineMode.CASE2_RAG_CHAT.value:
            gen_rules = []
        else:
            gen_rules = list(state.detection_rules or [])

        state.answer = _generate_answer(
            query,
            gen_context,
            history if _is_followup(query) else None,
            answer_style,
            needs_depth=intent.needs_synthesis or answer_style in (
                "professional", "record_lookup", "hybrid",
                "security_intelligence", "rule_draft",
            ),
            detection_rules=gen_rules,
            knowledge_domain=knowledge_domain.value,
            evidence=state.evidence,
            pipeline_mode=case_mode,
        )
        if answer_style == "rule_draft":
            state.answer = _finalize_rule_draft(
                state.answer,
                context=gen_context,
                detection_rules=gen_rules,
            )
            extracted = _extract_suricata_rules_for_ui(state.answer)
            if extracted:
                state.detection_rules = extracted
            from app.agent.rule_composer import ensure_summary_section, summarize_defined_rule

            state.answer = ensure_summary_section(state.answer, state.detection_rules or gen_rules)
            for r in state.detection_rules or []:
                if isinstance(r, dict) and not r.get("summary"):
                    r["summary"] = summarize_defined_rule(r)
        elif case_mode == PipelineMode.CASE3_POLICY_RULE.value:
            from app.agent.attack_history import is_new_attack_query

            if is_new_attack_query(query):
                cls = (state.agent_context or {}).get("_attack_classification") or {}
                expl = cls.get("explanation") or ""
                if expl and expl.lower() not in (state.answer or "").lower():
                    state.answer = (
                        "## Attack classification\n"
                        f"{expl}\n\n"
                        + (state.answer or "")
                    )
        state.answer = polish_user_answer(state.answer)
        # Case 2 only: strip raw SQL dumps. Case 3 may cite rule names in the draft.
        if case_mode == PipelineMode.CASE2_RAG_CHAT.value:
            state.answer = _reject_raw_sql_answer(state.answer, case_mode)
            if answer_style != "rule_draft":
                state.detection_rules = []

        state.citations = [
            {"source_type": e.get("type", ""), "source": e.get("source", "")}
            for e in state.evidence[:8]
        ]
        state.stages.append("reason")

    state.stages.append("respond")
    state.latency_ms = int((time.perf_counter() - t0) * 1000)
    try:
        from app.observability.trace import log_trace

        log_trace(state_to_response(state) | {"evidence": state.evidence[:12]})
    except Exception:
        pass
    return state


def _case3_rules_for_draft(rules: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Clean detection_rule rows for Case 3 drafting / UI (keep intent, drop raw SQL dumps)."""
    out: list[dict[str, Any]] = []
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        from app.agent.rule_composer import summarize_defined_rule

        cleaned = {
            "rule_name": r.get("rule_name") or r.get("name") or "",
            "protocol": r.get("protocol") or "",
            "category": r.get("category") or "",
            "action": r.get("action") or "",
            "attack_pattern_id": r.get("attack_pattern_id") or "",
            "detection_rule_id": r.get("detection_rule_id") or "",
            "summary": r.get("summary") or summarize_defined_rule(r),
            "grounded": True,
            "from": "case3_policy_resolve",
        }
        # Prefer Suricata text when enrolled — used for draft grounding, not raw dump.
        if r.get("suricata_text") or r.get("rule"):
            cleaned["rule"] = r.get("suricata_text") or r.get("rule")
        out.append(cleaned)
    return out


def _synthesize_policy_context(bundle: dict[str, Any] | None) -> dict[str, Any]:
    """Turn Case 3 Step-0 SQL rows into synthesis context (no raw row dump)."""
    b = dict(bundle or {})
    patterns = b.get("attack_patterns") or b.get("patterns") or []
    rules = b.get("detection_rules") or []
    lines: list[str] = []
    for p in patterns[:8]:
        if not isinstance(p, dict):
            continue
        name = p.get("name") or p.get("attack_pattern_id") or "pattern"
        proto = p.get("protocol") or ""
        cat = p.get("category") or ""
        obj = p.get("attack_objective") or p.get("description") or ""
        lines.append(f"- Attack pattern in scope: {name} ({proto} {cat}). {obj}".strip())
    for r in rules[:8]:
        if not isinstance(r, dict):
            continue
        rn = r.get("rule_name") or "rule"
        proto = r.get("protocol") or ""
        cat = r.get("category") or ""
        action = r.get("action") or ""
        rid = r.get("detection_rule_id") or ""
        lines.append(
            f"- Detection intent to draft: {rn}"
            + (f" [{rid}]" if rid else "")
            + f" — protocol={proto}, category={cat}, action={action}. "
            "Ground checks in Qdrant FS/Suricata evidence; paraphrase — do not paste SQL columns."
        )
    b["synthesis_brief"] = "\n".join(lines) if lines else (
        "Policy instruction in scope; draft detection rules from Qdrant FS/Suricata evidence."
    )
    return b


_RAW_SQL_ROW = re.compile(
    r"(\bDR\d{3}\b|\bAP\d{3}\b|detection_rule_id\s*=|attack_pattern_id\s*=|"
    r"rule_logic\s*=|validation_result\s*=|policy_id\s*=\s*\d{4,})",
    re.I,
)


_SOURCE_SECTION = re.compile(
    r"(?ims)^##\s*(source\s+linkage|sources?|references?|citations?|grounding)\s*\n.*?(?=^##\s|\Z)"
)
_SOURCE_LINE = re.compile(
    r"(?im)^(?:\s*[-*]|\d+\.)\s*.{0,40}(?:\.pdf\b|source\s*linkage|chunk_id|document\s*:).*$"
)
_PDF_HASH_NAME = re.compile(
    r"\b[0-9a-f]{8,}[_-][^ \n]*\.pdf\b",
    re.I,
)
_META_PHRASES = re.compile(
    r"(?i)\b(?:based on the (?:provided |retrieved )?(?:context|evidence)|"
    r"according to the (?:document|evidence|retrieved(?:\s+context)?|"
    r"retrieved(?:\s+evidence)?)|"
    r"from the (?:retrieved|provided) (?:context|evidence)|"
    r"the evidence (?:shows|indicates|states))\b[,:]?\s*"
)


def polish_user_answer(answer: str) -> str:
    """Strip citation / source sections and RAG meta-language from user-facing answers."""
    text = (answer or "").strip()
    if not text:
        return text
    text = _SOURCE_SECTION.sub("", text)
    text = "\n".join(
        line for line in text.splitlines() if not _SOURCE_LINE.match(line)
    )
    text = _PDF_HASH_NAME.sub("", text)
    text = _META_PHRASES.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def _reject_raw_sql_answer(answer: str, pipeline_mode: str | None) -> str:
    """Case 2 must not show raw SQL table-row dumps in the user-facing answer."""
    mode = (pipeline_mode or "").strip().lower()
    # Case 3 drafts may reference rule/pattern IDs — only gate Case 2 chatbot dumps.
    if mode != "case2_rag_chat":
        return answer or ""
    text = (answer or "").strip()
    if not text:
        return text
    hits = _RAW_SQL_ROW.findall(text)
    pipe_rows = text.count("|") >= 8 and re.search(
        r"detection_rule_id|rule_logic|validation_fields=", text, re.I
    )
    if len(hits) >= 3 or pipe_rows:
        cleaned: list[str] = []
        for line in text.splitlines():
            if _RAW_SQL_ROW.search(line) and ("=" in line or line.strip().startswith("|")):
                continue
            cleaned.append(line)
        text = "\n".join(cleaned).strip()
        if len(_RAW_SQL_ROW.findall(text)) >= 3:
            return (
                "## Answer\n\n"
                "Retrieved Qdrant evidence supports this topic, but the model response contained "
                "raw structured-table fragments and was withheld. Rephrase the question or ask "
                "for a standards-grounded summary (FS.11 / FS.19 / FS.20 / FS.21 / Suricata corpus)."
            )
    return text


def _needs_replan(evidence: list[dict[str, Any]], route: Any, query_type: str, agent_ctx: Any) -> bool:
    if not evidence:
        return True
    structured = [e for e in evidence if e.get("structured")]
    prose = [e for e in evidence if not e.get("structured")]
    if route is not None and getattr(route, "route", None) == STRUCTURED:
        return not structured
    if query_type in ("SECURITY_INVESTIGATION", "THREAT_ANALYSIS"):
        return len(prose) < 2
    if getattr(route, "uses_documents", False):
        return len(prose) < 1
    return False



def _ir21_identity_led(
    query: str,
    route: Any,
    structured: list[dict[str, Any]],
) -> bool:
    """True when the question is answered by IR.21 operator/network-element facts."""
    from app.agent.router import is_policy_led_query

    if is_policy_led_query(query):
        return False
    if route is not None and getattr(route, "uses_structured", False):
        tables = [str(t).lower() for t in (getattr(route, "tables", None) or [])]
        if any(t.startswith("ir21") for t in tables):
            return True
    ir21_rows = [
        e for e in structured
        if e.get("agent") == "ir21" or e.get("store") == "ir21_postgresql"
    ]
    if not ir21_rows:
        return False
    q = (query or "").lower()
    # Identity / capability tokens that live in IR.21 tables, not message_policy.
    identity = (
        "hlr", "hss", "msc", "vlr", "sgsn", "ggsn", "mme", "sgsn", "smsc", "gmsc",
        "global title", " gt ", "gt address", "tadig", "capv", " camel", "s6a",
        "iwf", "network element", "node type", "inbound", "outbound",
    )
    if not any(tok in q for tok in identity) and "gt" not in q.split():
        # Still treat as IR.21-led when a structured row clearly mirrors the query.
        qtoks = {t for t in re.findall(r"[a-z0-9]{3,}", q) if t not in {"the", "and", "for", "what", "which", "with", "from", "zain", "kuwait"}}
        for e in ir21_rows:
            body = str(e.get("body") or "").lower()
            if sum(1 for t in qtoks if t in body) >= 2:
                return True
        return False
    return True


def _prune_structured_for_query(
    query: str,
    rows: list[dict[str, Any]],
    *,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Keep structured evidence that overlaps the question; drop low-relevance noise."""
    if not rows:
        return []
    q = (query or "").lower()
    qtoks = {
        t for t in re.findall(r"[a-z0-9][a-z0-9./_-]{2,}", q)
        if t not in {"the", "and", "for", "what", "which", "with", "from", "this", "that"}
    }
    ir21_led = _ir21_identity_led(query, None, rows)
    scored: list[tuple[float, dict[str, Any]]] = []
    for e in rows:
        body = str(e.get("body") or "").lower()
        typ = str(e.get("type") or "")
        agent = str(e.get("agent") or "")
        base = float(e.get("score") or 0)
        hits = sum(1 for t in qtoks if t in body)
        if typ in ("Message Policy", "IDS", "Graph Fact"):
            base += 1.5 if not ir21_led else 0.2
        if agent == "ir21" or typ == "Structured Record":
            base += 2.0 if ir21_led else 0.0
        if hits:
            base += hits * 0.35
        elif typ == "Message Policy" and qtoks:
            base -= 1.0
        scored.append((base, e))
    scored.sort(key=lambda x: -x[0])
    return [e for _, e in scored[:limit]]


def _is_followup(query: str) -> bool:
    """Only self-contained questions should see prior turns.

    Without this, the LLM keeps answering the previous question when a new,
    unrelated one arrives.
    """
    import re

    q = (query or "").strip().lower()
    if len(q.split()) <= 4:
        return True
    return bool(
        re.search(
            r"\b(it|its|that|those|these|them|this one|same|above|previous|"
            r"also|instead|what about|and the)\b",
            q,
        )
    )


def _finalize_rule_draft(
    answer: str,
    *,
    context: str,
    detection_rules: list[dict[str, Any]] | None = None,
) -> str:
    """Validate and repair Suricata syntax in rule-draft answers."""
    from app.ontology.suricata_compiler import ensure_rule_draft_answer

    return ensure_rule_draft_answer(
        answer,
        context=context,
        detection_rules=detection_rules,
    )


def _extract_suricata_rules_for_ui(answer: str) -> list[dict[str, Any]]:
    """Build detection_rules sidebar entries from validated Suricata lines."""
    from app.ontology.suricata_compiler import extract_rules_from_text, validate_rule_line

    out: list[dict[str, Any]] = []
    for line in extract_rules_from_text(answer or ""):
        v = validate_rule_line(line)
        if not v["valid"]:
            continue
        out.append(
            {
                "rule": line,
                "suricata_text": line,
                "sid": v.get("sid") or "",
                "rule_name": v.get("msg") or "",
                "grounded": True,
                "from": "rule_draft",
            }
        )
    return out


def _generate_answer(
    query: str,
    context: str,
    history: list[dict[str, str]] | None,
    style: str,
    *,
    needs_depth: bool = False,
    detection_rules: list[dict[str, Any]] | None = None,
    knowledge_domain: str | None = None,
    evidence: list[dict[str, Any]] | None = None,
    pipeline_mode: str | None = None,
) -> str:
    """Retrieve-grounded generation — stream tokens to the UI as they are produced."""
    from shared.llm import answer_question, is_llm_available, _emit_token

    synth_context = (context or "").strip()
    if not is_llm_available():
        msg = (
            "The local generator is unavailable. Retrieved evidence is shown in the panel; "
            "retry once the model is loaded."
        )
        _emit_token(msg)
        return msg

    import config as _cfg

    tokens = max(int(getattr(_cfg, "MAX_NEW_TOKENS", 1024) or 1024), 1024)
    if needs_depth:
        tokens = max(tokens, 1400)
    ctx_limit = int(getattr(_cfg, "CONTEXT_MAX_CHARS", 48000) or 48000)
    if len(synth_context) > ctx_limit:
        synth_context = "[truncated]\n" + synth_context[-ctx_limit:]

    # Always stream so the UI paints each piece as the model generates.
    answer = answer_question(
        query,
        synth_context,
        history=history,
        max_tokens=tokens,
        style=style or "professional",
        stream=True,
    )
    answer = (answer or "").strip()
    if not answer:
        msg = "No answer was generated. Check the evidence panel or rephrase the question."
        _emit_token(msg)
        return msg
    return answer


def _lacks_professional_structure(answer: str, style: str) -> bool:
    """True when the LLM returned unstructured prose instead of a sectioned brief."""
    text = (answer or "").strip()
    if not text or style in ("rule_draft", "security_intelligence"):
        return False
    # Deterministic grounded briefs already use ## headings.
    if text.startswith("## "):
        return text.count("## ") < 2 and style == "professional"
    return style == "professional"


def _answer_from_evidence(query: str, context: str) -> str | None:
    """Professional lookup brief when the LLM is unavailable."""
    from app.retrieval.table_chunk_search import build_lookup_answer

    return build_lookup_answer(query, context)


def _answer_from_detection_rules(
    query: str,
    context: str,
    detection_rules: list[dict[str, Any]] | None = None,
    *,
    pipeline_mode: str | None = None,
) -> str | None:
    """Deterministic brief from enrolled detection_rule / Suricata evidence.

    Case 2 never recovers SQL-shaped DR/AP rows from context — those belong to
    Case 1/3 or explicit Suricata syntax questions.
    """
    from app.agent.knowledge_domains import is_qdrant_only_case

    mode = (pipeline_mode or "").strip().lower()
    rules = list(detection_rules or [])
    # Case 2: do not scrape detection_rule_id= / AP00x from tool-doc prose.
    if not rules and not is_qdrant_only_case(mode):
        for m in re.finditer(
            r"detection_rule_id=(DR\d{3}).*?attack_pattern_id=(AP\d{3}).*?rule_name=([^;\n]+)",
            context or "",
            re.I | re.S,
        ):
            rules.append(
                {
                    "detection_rule_id": m.group(1).upper(),
                    "attack_pattern_id": m.group(2).upper(),
                    "summary": m.group(0)[:500],
                    "rule": "",
                    "sid": "",
                    "grounded": True,
                }
            )
    if not rules:
        # Suricata alert lines are OK when the user asked about Suricata/SID.
        if mode == "case2_rag_chat" and not re.search(
            r"\b(suricata|sid\s*:|tshark|wireshark)\b", (query or "").lower()
        ):
            return None
        for m in re.finditer(
            r'(alert|drop)\s+[^\n]+sid\s*:\s*(\d+)[^\n]*',
            context or "",
            re.I,
        ):
            rules.append({"rule": m.group(0).strip()[:400], "sid": m.group(2), "grounded": True})
    if not rules:
        return None

    q = (query or "").lower()
    scored: list[tuple[int, dict[str, Any]]] = []
    for rule in rules:
        blob = " ".join(
            str(rule.get(k) or "")
            for k in ("summary", "rule", "detection_rule_id", "attack_pattern_id", "source", "sid")
        ).lower()
        if not blob.strip():
            continue
        hits = sum(1 for t in re.findall(r"[a-z0-9]{3,}", q) if t in blob)
        # Prefer exact AP/DR / rule-name / sid hits.
        if re.search(r"\b(ap\d{3}|dr\d{3})\b", q):
            for m in re.finditer(r"\b(ap\d{3}|dr\d{3})\b", q):
                if m.group(1) in blob:
                    hits += 5
        if "sid" in q:
            sid = str(rule.get("sid") or "")
            if sid and sid in q.replace(" ", ""):
                hits += 5
            elif sid and sid in blob:
                hits += 1
        scored.append((hits, rule))
    scored.sort(key=lambda x: -x[0])
    if not scored or scored[0][0] <= 0:
        # Still usable when the question is clearly about rules and we have grounded rows.
        if not any(k in q for k in ("rule", "suricata", "attack", "detect", "sid", "ap0", "dr0", "hijack")):
            return None
        top = [r for _, r in scored[:3]]
    else:
        top = [r for h, r in scored[:3] if h > 0] or [scored[0][1]]

    lines = ["## Detection rule (from enrolled knowledge)"]
    for rule in top:
        summary = str(rule.get("summary") or "").strip()
        text = str(rule.get("rule") or "").strip()
        src = str(rule.get("source") or "")
        sid = str(rule.get("sid") or "")
        if summary:
            lines.append(f"- {summary}" + (f" ({src})" if src else ""))
        if text:
            lines.append(f"- Suricata: `{text}`" + (f" sid:{sid}" if sid and f"sid:{sid}" not in text.lower() else ""))
        if not summary and not text and src:
            lines.append(f"- {src}")
    return "\n".join(lines) if len(lines) > 1 else None


def _answer_ignores_ids_evidence(answer: str, ids_brief: str | None) -> bool:
    """True when grounded IDS ids are present but the answer never cites them."""
    if not ids_brief:
        return False
    low = (answer or "").lower()
    if "confident synthesized" in low or not low.strip():
        return True
    ids = set(re.findall(r"\b(?:ap|dr)\d{3}\b", ids_brief.lower()))
    sids = set(re.findall(r"\bsid\s*:\s*(\d+)", ids_brief.lower()))
    sids |= set(re.findall(r"\b(9000\d{2})\b", ids_brief.lower()))
    if not ids and not sids:
        return False
    cited = any(i in low for i in ids) or any(s in low for s in sids)
    # Also accept rule-name fragments from the brief.
    names = re.findall(r"rule_name=([A-Z0-9._-]+)", ids_brief, re.I)
    cited = cited or any(n.lower() in low for n in names if len(n) >= 8)
    return not cited


def _is_garbled_table(answer: str) -> bool:
    """Detect LLM tables where Field and Value columns are duplicated/swapped."""
    import re

    rows = re.findall(r"\|\s*([^|\n]+)\s*\|\s*([^|\n]+)\s*\|", answer or "")
    if len(rows) < 2:
        return False
    same = 0
    for left, right in rows[1:]:
        a, b = left.strip().lower(), right.strip().lower()
        if a.startswith("---") or b.startswith("---"):
            continue
        if a == b and len(a) >= 4:
            same += 1
    return same >= 2


def _parse_brief_pairs(brief: str) -> dict[str, str]:
    import re

    pairs: dict[str, str] = {}
    for m in re.finditer(
        r"\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|",
        brief or "",
    ):
        field, value = m.group(1).strip(), m.group(2).strip()
        if field.lower() in ("field", "---", ":---") or value.startswith("---"):
            continue
        pairs[field.lower()] = value
    return pairs


_NEGATION_RE = (
    r"\b(n/?a|not specified|not documented|not stated|does not specify|"
    r"no support|not supported|not provided|unspecified)\b"
)

_EMPTY_VALUES = ("n/a", "—", "-", "none", "")


def _brief_is_relevant(query: str, brief: str | None) -> bool:
    """Guard against substituting a brief that answers a different question."""
    import re

    if not brief:
        return False
    stop = {
        "what", "which", "does", "the", "are", "for", "from", "with", "list",
        "all", "show", "give", "find", "any", "document", "documents", "table",
        "section", "page", "support", "supported", "listed", "include", "each",
    }
    terms = {t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 4 and t not in stop}
    if not terms:
        return True
    low = brief.lower()
    return any(t in low for t in terms)


def _value_present(value: str, answer: str) -> bool:
    """Whether the answer states a value, tolerating punctuation and wording.

    Evidence cells like "CAPv1 CAPv2 CAPv3" are legitimately rendered as
    "CAPv1, CAPv2 and CAPv3", so compare on tokens rather than raw substrings.
    """
    import re

    parts = [p for p in re.split(r"[\s,;/|]+", (value or "").lower()) if len(p) >= 2]
    if not parts:
        return True
    low = (answer or "").lower()
    return all(p in low for p in parts)


def _lookup_contradicts_evidence(answer: str, brief: str | None) -> bool:
    """True when the answer denies a field that evidence gives a value for."""
    import re

    pairs = _parse_brief_pairs(brief or "")
    if not pairs:
        return False
    low = (answer or "").lower()
    for field, value in pairs.items():
        val = value.strip().lower()
        if val in _EMPTY_VALUES or len(val) < 2:
            continue
        label = re.escape(field.strip().lower())[:60]
        if not label:
            continue
        # Answer names the field, then denies it, without ever citing the value.
        if re.search(rf"{label}[^\n.|]{{0,80}}{_NEGATION_RE}", low) and not _value_present(val, low):
            return True
    return False


def _lookup_missing_known_values(answer: str, brief: str) -> bool:
    """True when the answer drops the most query-relevant documented value."""
    pairs = _parse_brief_pairs(brief)
    low = (answer or "").lower()
    # Brief rows are ranked by query relevance; only the leading ones are
    # strong enough evidence to override the model's own phrasing.
    for _, value in list(pairs.items())[:2]:
        val = value.strip().lower()
        if len(val) < 3 or val in _EMPTY_VALUES:
            continue
        if not _value_present(val, low):
            return True
    return False


def _is_incomplete_lookup_answer(answer: str, query: str) -> bool:
    """Detect thin table stubs that don't actually answer the question."""
    text = (answer or "").strip()
    if not text:
        return True
    low = text.lower()
    q = (query or "").lower()
    # Single table-title stub without message/parameter content.
    if re.search(r"\bwhich\b", q) and re.search(r"\bmessages?\b", q):
        if "table" in low and not re.search(
            r"\b(ulr|air|create session|modify bearer|ati|psi|sendauthentication)\b", low
        ):
            if low.count("- ") < 2 and "associated messages" not in low:
                return True
    if re.search(r"\bparameters?\b", q) and re.search(r"\bvalidat", q):
        if not re.search(r"origin-host|origin-realm|imsi|vplmn|apn|teid|parameter", low):
            return True
    return False


def _is_weak_answer(answer: str, query: str, *, needs_synthesis: bool = False) -> bool:
    import re

    text = (answer or "").strip()
    if not text:
        return True
    low = text.lower()
    if low in ("insufficient evidence.", "insufficient evidence", "no.", "yes.", "n/a", "none"):
        return True
    if len(text) < 40:
        return True
    if "please provide a specific question" in low:
        return True
    if "values extracted from document table rows" in low:
        return True
    if any(
        p in low
        for p in (
            "unable to find information",
            "answer not found",
            "could not produce a confident",
            "did not contain structured values",
            "i don't know",
            "i do not know",
            "no relevant information",
            "not enough information",
            "do not have enough information",
            "don't have enough information",
            "based on the provided context",
            "cannot answer",
            "can't answer",
        )
    ):
        return True
    if _is_incomplete_lookup_answer(answer, query):
        return True
    if text.endswith("?") and len(text) < 220:
        return True

    if needs_synthesis:
        # Structured professional briefs with a table are acceptable even if shorter.
        if ("| :---" in text or "| Field |" in text) and len(text) >= 160:
            return False
        min_len = min(500, max(200, len(query) * 2))
        if len(text) < min_len:
            return True
        stop = frozenset({
            "what", "which", "where", "when", "does", "from", "that", "this",
            "with", "have", "been", "would", "could", "should", "about", "their",
            "explain", "describe",
        })
        terms = [w for w in re.findall(r"[a-z]{5,}", query.lower()) if w not in stop]
        if terms:
            coverage = sum(1 for w in terms if w in low) / len(terms)
            if coverage < 0.3:
                return True
        return False

    q_words = [w for w in query.lower().split() if len(w) > 4][:6]
    if len(text) < 120 and sum(1 for w in q_words if w in low) >= 3:
        return True
    return False


def _estimate_confidence(state: AgentState) -> str:
    if not state.evidence:
        return "INSUFFICIENT"
    types = {e.get("type") for e in state.evidence}
    if len(state.evidence) >= 3 and ("IDS" in types or "Threat Knowledge" in types):
        return "HIGH"
    if len(state.evidence) >= 2:
        return "MEDIUM"
    return "LOW"


def state_to_response(state: AgentState) -> dict[str, Any]:
    chunks = evidence_to_chunks(state.evidence)
    mode = (state.pipeline_mode or "").strip().lower()
    # Case 2: no detection_rules. Case 3: include resolved/cleaned rules & detections.
    if mode == "case2_rag_chat":
        rules: list[dict[str, Any]] = []
    else:
        rules = list(state.detection_rules or [])
    return {
        "answer": state.answer,
        "query_type": state.query_type,
        "confidence": state.confidence,
        "enhanced_query": state.enhanced_query,
        "expanded_terms": state.expanded_terms,
        "candidate_sources": state.candidate_sources,
        "tools_used": state.tools_used,
        "evidence": state.citations,
        "citations": state.citations,
        "chunks": chunks,
        "hits": len(chunks),
        "trace_id": state.trace_id,
        "latency_ms": state.latency_ms,
        "stages": state.stages,
        "agent_context": state.agent_context,
        "round1_documents": state.round1_documents,
        "finding": state.finding,
        "replanned": state.replanned,
        "route": state.route.as_dict() if state.route is not None else None,
        "specialists": state.specialists,
        "knowledge_kinds": state.knowledge_kinds,
        "detection_rules": rules,
        "detection_rule_ids": [
            r.get("detection_rule_id") or str(r.get("source") or "").split(":")[-1]
            for r in rules
            if r.get("detection_rule_id") or str(r.get("source") or "").startswith("detection_rule:")
        ],
        "knowledge_domain": (state.agent_context or {}).get("_knowledge_domain"),
        "domain_meta": (state.agent_context or {}).get("_domain_meta"),
        "pipeline_mode": state.pipeline_mode,
        "ids_verification": state.ids_verification,
        "reports": state.reports,
    }
