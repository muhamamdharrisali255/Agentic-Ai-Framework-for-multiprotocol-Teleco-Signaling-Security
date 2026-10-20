"""Standards-domain synthesis helpers — FS prose only, no IDS/policy bleed."""

from __future__ import annotations

import re

_TOOL_DOC_MARKERS = re.compile(
    r"\b(suricata|tshark|wireshark|detection[_\s-]?rule|\.rules\.txt)\b",
    re.I,
)
_DETECTION_QUERY = re.compile(
    r"\b(suricata|detection\s+rule|ids\s+rule|enrolled\s+rule|attack\s+pattern|"
    r"\bap\d{3}\b|\bdr\d{3}\b|\bsid\b|create\s+a\s+rule|draft\s+a\s+rule)\b",
    re.I,
)
_RULE_DUMP = re.compile(
    r"##\s*detection\s+rule|suricata:\s*`alert|sid:\s*9000\d{2}",
    re.I,
)
_ATTACK_TOPIC = re.compile(
    r"\b(attack\s+scenario|dos\s+attack|countermeasure|exploit|vulnerability|threat)\b",
    re.I,
)
_MSG_ABBREV = re.compile(
    r"\b(ulr|ula|air|aia|clr|cla|idr|ida|pur|pua|nor|noa|rsr|rsa|"
    r"create\s*session(?:\s*request)?|delete\s*session(?:\s*request)?|"
    r"modify\s*bearer(?:\s*request)?|create\s*pdp(?:\s*context)?|"
    r"update\s*pdp(?:\s*context)?|delete\s*pdp(?:\s*context)?|"
    r"update\s*location|echo\s*request|echo\s*response)\b",
    re.I,
)
_SOURCE_BLOCK = re.compile(
    r"SOURCE\s+(\d+)(?:\s*\([^)]*\))?:\s*\nType:\s*([^\n]+)\nSource:\s*([^\n]+)\n(?:chunk_id:[^\n]*\n)?Evidence:\s*\n",
    re.I,
)


def format_professional_brief(
    answer: str,
    *,
    sections: list[tuple[str, str]] | None = None,
    source_rows: list[tuple[str, str, str]] | None = None,
) -> str:
    """Wrap grounded fallback text in the same ## structure as LLM answers."""
    lines = ["## Answer", "", (answer or "").strip(), ""]
    for title, body in sections or []:
        if not body:
            continue
        lines += [f"## {title}", "", body.strip(), ""]
    return "\n".join(lines).strip()


def wants_detection_answer(query: str) -> bool:
    return bool(_DETECTION_QUERY.search(query or ""))


def is_rule_dump_answer(answer: str) -> bool:
    return bool(_RULE_DUMP.search(answer or ""))


def _query_terms(query: str) -> list[str]:
    stop = {
        "what", "which", "does", "the", "are", "for", "from", "with", "that", "this",
        "between", "normally", "associated", "should", "would", "about", "their",
        "difference", "messages", "message", "signaling", "signalling",
    }
    return [
        t
        for t in re.findall(r"[a-z0-9][a-z0-9.\-]{2,}", (query or "").lower())
        if t not in stop
    ]


def _score_block(query: str, body: str, source: str, etype: str) -> float:
    q = (query or "").lower()
    blob = f"{source} {body}".lower()
    terms = _query_terms(query)
    if not terms:
        return 0.0
    hits = sum(1 for t in terms if t in blob)
    score = float(hits)
    if etype.lower() == "domain dictionary":
        score += 0.4
    if etype.lower() == "table":
        score += 2.0
    if etype.lower() == "document":
        score += 0.8
    if "category" in q and "category" in blob:
        score += 1.0
    if re.search(r"3\.1", q) and re.search(r"3\.1", blob):
        score += 3.0
    if re.search(r"3\.2", q) and re.search(r"3\.2", blob):
        score += 3.0
    if re.search(r"cat[-\s]?3\.1", q) and re.search(r"cat[-\s]?3\.1|category[-\s]?3\.1", blob):
        score += 4.0
    if re.search(r"cat[-\s]?3\.2", q) and re.search(r"cat[-\s]?3\.2|category[-\s]?3\.2", blob):
        score += 4.0
    if re.search(r"\bvalidat", q) and re.search(r"\bvalidat|parameter|origin-host|imsi", blob):
        score += 2.0
    if re.search(r"\bprohibit", q) and re.search(r"\bprohibit|forbidden|never|block|unauthor", blob):
        score += 2.0
    if re.search(r"\bmcc\b|\bmnc\b", q) and re.search(r"\bmcc\b|\bmnc\b", blob):
        score += 3.0
    # Exact section numbers from the query (e.g. 4.3.5) should float matching passages.
    for sec in re.findall(r"\b\d+\.\d+(?:\.\d+)?\b", q):
        if sec in blob:
            score += 4.0
    if _ATTACK_TOPIC.search(blob) and not re.search(r"\battack\s+category", blob):
        score -= 2.0
    # Do not apply FS taxonomy boost/demote here — retrieval ranking already selected evidence.
    return score


def is_evidence_paste_answer(answer: str) -> bool:
    """True when the text is a raw evidence dump, not a synthesized brief."""
    text = (answer or "").strip()
    if not text:
        return False
    if is_rule_dump_answer(text):
        return True
    low = text.lower()
    if "relevant values:" in low and len(text) > 600:
        return True
    if text.startswith("## Prohibited / restricted signaling") and "**" in text:
        if "| Message |" not in text and "| Example |" not in text:
            return True
    # Long FS rule fragments without a proper answer table.
    if "b ss7 firewall recommendations" in low and len(text) > 900:
        if text.count("## ") < 3:
            return True
    return False


def standards_evidence_brief(query: str, evidence: list[dict] | None) -> str | None:
    """Grounded brief built directly from retrieved evidence rows (dictionary/tables)."""
    if not evidence:
        return None
    q = (query or "").lower()

    # Category definitions: LLM synthesizes from evidence (no template short-circuit).

    if re.search(r"difference\s+between", q):
        brief = _dictionary_comparison_brief(query, evidence)
        if brief:
            return brief

    if re.search(r"\bparameters?\b", q) and re.search(r"\bvalidat", q):
        brief = _parameter_table_brief(query, evidence)
        if brief:
            return brief

    if re.search(r"\bwhich\b", q) and re.search(r"\bmessages?\b", q):
        brief = _message_list_brief(query, evidence)
        if brief:
            return brief

    if re.search(r"\bwhy\b", q) and re.search(r"\bmcc\b|\bmnc\b", q):
        brief = _mcc_mnc_reason_brief(query, evidence)
        if brief:
            return brief

    if re.search(r"\bprohibit", q) or re.search(r"\bforbidden\b", q):
        brief = _prohibited_messages_brief(query, evidence)
        if brief:
            return brief

    return None


def _is_category_definition_query(q: str) -> bool:
    q = (q or "").lower()
    if re.search(r"\bdifference\s+between", q):
        return False
    if re.search(r"\bprohibit|\bforbidden\b|\bwhich\b.*\bmessages?\b|\bparameters?\b", q):
        return False
    return bool(
        re.search(r"\bwhat\s+is\b.*\b(category|cat)[-\s]?[123]", q)
        or re.search(r"\b(define|definition\s+of)\b.*\b(category|cat)[-\s]?[123]", q)
        or re.search(r"\b(category|cat)[-\s]?[123][a-z0-9.]*\s+(signaling|signalling)?\s*message", q)
    )


def _wanted_category_keys(query: str) -> list[str]:
    q = (query or "").lower()
    if re.search(r"3\.1|cat[-\s]?3\.1|category[-\s]?3\.1", q):
        return ["3.1", "cat3.1", "category-3.1", "category 3.1"]
    if re.search(r"3\.2|cat[-\s]?3\.2|category[-\s]?3\.2", q):
        return ["3.2", "cat3.2", "category-3.2", "category 3.2"]
    if re.search(r"category[-\s]?1|\bcat[-\s]?1\b", q):
        return ["category-1", "category 1", "cat1", "cat-1"]
    if re.search(r"category[-\s]?2|\bcat[-\s]?2\b", q):
        return ["category-2", "category 2", "cat2", "cat-2"]
    if re.search(r"category[-\s]?3|\bcat[-\s]?3\b", q):
        return ["category-3", "category 3", "cat3", "cat-3"]
    return []


def _category_definition_brief(query: str, evidence: list[dict]) -> str | None:
    """Professional structured CAT definition: definition → model table → examples → ops → sources."""
    want = _wanted_category_keys(query)
    if not want:
        return None

    focus = "CAT1"
    if any("3.1" in w for w in want):
        focus = "CAT3.1"
    elif any("3.2" in w for w in want):
        focus = "CAT3.2"
    elif any(re.fullmatch(r".*3.*", w) and "1" not in w and "2" not in w for w in want):
        focus = "CAT3"
    elif any("2" in w and "3" not in w for w in want):
        focus = "CAT2"
    elif any("1" in w and "3" not in w for w in want):
        focus = "CAT1"

    tax = _roaming_category_catalog()
    focus_meta = tax.get(focus) or {}
    formal = str(focus_meta.get("label") or focus)
    source_ref = str(focus_meta.get("source") or "GSMA FS.21 §7.2")
    definition = str(focus_meta.get("description") or "").strip()

    # Prefer dictionary / FS prose when present (may be richer than taxonomy JSON).
    dict_hits: list[tuple[str, str]] = []
    doc_hits: list[tuple[str, str]] = []
    for e in evidence or []:
        typ = str(e.get("type") or "")
        src = str(e.get("source") or "")
        body = str(e.get("body") or "").strip()
        if not body:
            continue
        blob = f"{src} {body}".lower()
        if not any(w in blob for w in want):
            continue
        if focus == "CAT1" and re.search(r"inbound roamer|category\s*2 filtering", blob):
            if not re.search(r"category[-\s]?1|cat1|interface-unauthor", blob):
                continue
        if typ == "Domain Dictionary":
            dict_hits.append((src, body))
        elif typ == "Document" and (
            "fs.21" in blob or "fs.19" in blob or "7.2" in blob or "categor" in blob
        ):
            if len(body) >= 60:
                doc_hits.append((src, body[:1100]))

    if dict_hits or doc_hits:
        picked_body, picked_src = (dict_hits or doc_hits)[0]
        for src, body in dict_hits + doc_hits:
            low = body.lower()
            if any(
                k in low
                for k in (
                    "interface-unauthor",
                    "home-network",
                    "plausible",
                    "partner-unauthor",
                    "sequence",
                    "context",
                    "addressing correlation",
                    "time-location",
                )
            ):
                picked_body, picked_src = body, src
                break
        cleaned = re.sub(
            r"^(?:category[-\s]?[123](?:\.[12])?|cat[-\s]?[123](?:\.[12])?)\s*[:\-–]?\s*",
            "",
            picked_body.strip(),
            flags=re.I,
        )
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        # Prefer taxonomy formal name when gloss embeds "Label: rest"
        m = re.match(r"^([^:]{8,60}):\s*(.+)$", cleaned)
        if m and not definition:
            formal = m.group(1).strip()
            definition = m.group(2).strip()
        elif cleaned:
            # If gloss starts with formal name, split; else use full text as definition.
            if formal.lower() in cleaned.lower() and ":" in cleaned:
                definition = cleaned.split(":", 1)[-1].strip()
            else:
                definition = cleaned
        if picked_src and "FS." in picked_src:
            source_ref = picked_src
    elif not definition:
        return None

    if len(definition) > 900:
        definition = definition[:900].rsplit(" ", 1)[0] + "…"

    label = {
        "CAT1": "Category-1 (CAT1)",
        "CAT2": "Category-2 (CAT2)",
        "CAT3": "Category-3 (CAT3)",
        "CAT3.1": "Category-3.1",
        "CAT3.2": "Category-3.2",
    }.get(focus, focus)

    # Related categories for contextual linkage table.
    related_rows: list[tuple[str, str, str]] = []
    order = ["CAT1", "CAT2", "CAT3", "CAT3.1", "CAT3.2"]
    for key in order:
        meta = tax.get(key) or {}
        if not meta:
            continue
        if focus.startswith("CAT3") and key in ("CAT1", "CAT2", "CAT3", "CAT3.1", "CAT3.2"):
            related_rows.append((key, str(meta.get("label") or ""), str(meta.get("source") or "")))
        elif focus in ("CAT1", "CAT2", "CAT3") and key in ("CAT1", "CAT2", "CAT3"):
            related_rows.append((key, str(meta.get("label") or ""), str(meta.get("source") or "")))

    # Examples from message-policy / FS document bullets (evidence only).
    # If retrieve skipped policy specialist, pull matching CAT rows for examples.
    enriched = list(evidence or [])
    if not any(e.get("type") == "Message Policy" for e in enriched):
        try:
            from app.ontology.policy_knowledge import search_policy

            pol = search_policy(query) or {}
            for row in (pol.get("evidence") or [])[:4]:
                if str(row.get("type") or "") != "Message Policy":
                    continue
                body_l = str(row.get("body") or "").lower()
                # Keep only rows that match the asked category.
                want_tag = focus.lower().replace("cat", "cat")
                if focus.lower() in body_l or want_tag in body_l:
                    enriched.append(row)
                elif focus == "CAT1" and "cat1" in body_l:
                    enriched.append(row)
                elif focus == "CAT2" and "cat2" in body_l:
                    enriched.append(row)
                elif focus.startswith("CAT3") and "cat3" in body_l:
                    enriched.append(row)
        except Exception:
            pass
    examples = _category_examples_from_evidence(focus, enriched)

    # Extra FS detail bullets from document hits (not the same as definition).
    detail_bullets: list[str] = []
    for _, body in doc_hits[:3]:
        for para in re.split(r"\n+", body):
            p = re.sub(r"\s+", " ", para).strip(" -•\t")
            if len(p) < 40:
                continue
            if p.lower().startswith("relevant values"):
                continue
            # Drop TOC / breadcrumb paths (e.g. "7 Foo > 7.2 Bar > 7.2.1 …").
            if p.count(">") >= 1 and re.search(r"^\d+\s+\S+", p):
                continue
            if formal.lower() in p.lower() or any(w in p.lower() for w in want):
                # Prefer a complete sentence when present.
                sentences = [
                    s.strip()
                    for s in re.split(r"(?<=[.!?])\s+", p)
                    if len(s.strip()) >= 40
                ]
                candidate = ""
                for s in sentences:
                    if formal.lower() in s.lower() or any(w in s.lower() for w in want):
                        candidate = s
                        break
                if not candidate:
                    candidate = sentences[0] if sentences else p
                candidate = candidate[:280].rstrip(" ,;:")
                # Skip mid-phrase fragments ("… received from").
                if re.search(r"\b(from|the|a|an|to|of|and|or|for)$", candidate, re.I):
                    continue
                if candidate not in detail_bullets and definition[:80].lower() not in candidate.lower():
                    detail_bullets.append(candidate)
            if len(detail_bullets) >= 3:
                break
        if len(detail_bullets) >= 3:
            break

    ops = _category_ops_notes(focus)
    example_table, example_notes = _split_category_examples(examples)

    # Prefer short FS detail bullets; fold leftover example notes only if they add new info.
    def _detail_key(text: str) -> str:
        return re.sub(r"\s+", " ", text.lower())[:90]

    seen_detail = {_detail_key(b) for b in detail_bullets}
    for note in example_notes:
        key = _detail_key(note)
        # Skip long FS-extract dumps that largely repeat an existing short bullet.
        if any(key[:50] in sk or sk[:50] in key for sk in seen_detail):
            continue
        detail_bullets.append(note)
        seen_detail.add(key)
        if len(detail_bullets) >= 4:
            break

    bridge = (
        f"Reading order: definition → where {label} sits among CAT1/2/3 → "
        "what the firewall does → concrete examples → supporting FS wording."
    )

    lines: list[str] = [
        "## Definition",
        "",
        f"**{label}** — *{formal}*",
        "",
        definition,
        "",
        "This category is one facet of interconnect packet classification: it tells the "
        "signalling firewall **what kind of check** applies at the point of interconnect.",
        "",
        f"*{bridge}*",
        "",
        "## Place in the category model",
        "",
        "How this category relates to the rest of the interconnect classification model:",
        "",
        "| Category | Formal name | Control posture |",
        "| --- | --- | --- |",
    ]
    for key, lab, src in related_rows:
        _ = src
        mark = " ← **this question**" if key == focus else ""
        posture = {
            "CAT1": "Block by default on interconnect",
            "CAT2": "Allow only with partner / bilateral context",
            "CAT3": "Allow with sequence / context validation",
            "CAT3.1": "Sequence-aware validation",
            "CAT3.2": "Context-aware validation",
        }.get(key, "Policy-driven screening")
        lines.append(f"| {key}{mark} | {lab} | {posture} |")

    lines += [
        "",
        "## Operational meaning",
        "",
        f"What {label} implies for interconnect screening (follows from the definition above):",
        "",
    ]
    for b in ops:
        lines.append(f"- {b}")

    if example_table:
        lines += [
            "",
            "## Examples (from enrolled evidence)",
            "",
            f"Concrete signalling messages enrolled under the same CAT class as **{label}**:",
            "",
            *example_table,
        ]
    else:
        lines += [
            "",
            "## Examples",
            "",
            f"- No named message examples were present in the current evidence pack for {label}. "
            "Use Message Policy / FS CAT tables when available.",
        ]

    if detail_bullets:
        lines += [
            "",
            "## Related detail from the specification",
            "",
            "Supporting wording from the same category discussion in the FS extract:",
            "",
        ]
        for b in detail_bullets:
            lines.append(f"- {b}")

    lines += [
        "",
        "## Operational control",
        "",
        "- Enforce interconnect screening against the category model (CAT1 / CAT2 / CAT3).",
        "- Apply bilateral exceptions only where the policy explicitly allows them.",
        "- Prefer message-policy rows with CAT labels for concrete OpCode / message examples.",
    ]
    if focus in ("CAT3.1", "CAT3.2"):
        lines += [
            "",
            f"For Diameter {focus}, apply the S6a / interconnect validation checks that distinguish "
            "sequence-aware vs context-aware enforcement.",
        ]

    return "\n".join(lines).strip()


def _roaming_category_catalog() -> dict[str, dict]:
    """Flatten taxonomy roaming_categories into CAT* → {label, description, source}."""
    out: dict[str, dict] = {}
    try:
        from app.ontology.taxonomy import load_taxonomy

        tax = load_taxonomy() or {}
        cats = tax.get("roaming_categories") or {}
        for key, meta in cats.items():
            if not isinstance(meta, dict):
                continue
            out[key] = {
                "label": meta.get("label") or key,
                "description": meta.get("description") or "",
                "source": meta.get("source") or "",
            }
            for ck, child in (meta.get("children") or {}).items():
                if isinstance(child, dict):
                    out[ck] = {
                        "label": child.get("label") or ck,
                        "description": child.get("description") or "",
                        "source": child.get("source") or "",
                    }
    except Exception:
        pass
    return out


def _category_ops_notes(focus: str) -> list[str]:
    if focus == "CAT1":
        return [
            "Applies to packets that are **not expected on this interconnect interface** (intra-network use).",
            "Default interconnect control: **BLOCK / drop** unless a bilateral agreement explicitly allows exchange.",
            "Links to firewall design: CAT1 filtering is interface-authorisation, not partner or sequence validation.",
        ]
    if focus == "CAT2":
        return [
            "Applies to packets about a subscriber that should come from the **home / allocated** network context.",
            "Screen for inconsistencies between lower-layer and application-layer identity (inbound roamer protection).",
            "Links to firewall design: CAT2 is partner / home-network validation — not a blanket interconnect ban.",
        ]
    if focus == "CAT3":
        return [
            "Applies to packets that claim to come from the subscriber's **current / purported visited** network.",
            "Requires correlation and plausibility (location, velocity, time) across the signalling context.",
            "Links to firewall design: CAT3 is deeper than CAT1 allow/deny and CAT2 partner checks.",
        ]
    if focus == "CAT3.1":
        return [
            "Subtype of CAT3: compare **previous time/location** (or last update) with current Origin-Host / Origin-Realm.",
            "Used to catch implausible velocity / non-bordering country jumps between updates.",
            "Links to Diameter interconnect screening (FS.19) under the CAT3 umbrella (FS.21).",
        ]
    if focus == "CAT3.2":
        return [
            "Subtype of CAT3: correlate **address fields inside one packet** (e.g. VPLMN, Origin-Host, Origin-Realm on ULR/AIR).",
            "Detects internal inconsistencies that indicate abnormal or spoofed context.",
            "Links to Diameter interconnect screening (FS.19) under the CAT3 umbrella (FS.21).",
        ]
    return ["Requires validation beyond simple interconnect allow/deny."]


def _category_examples_from_evidence(focus: str, evidence: list[dict] | None) -> list[str]:
    """Evidence-backed examples; prefer a small table for policy message examples."""
    rows: list[tuple[str, str, str]] = []
    bullets: list[str] = []
    focus_l = focus.lower()
    why_by_focus = {
        "cat1": "Treated as CAT1 / interface-unauthorised class traffic",
        "cat2": "Treated as CAT2 / home-network class traffic",
        "cat3": "Treated as CAT3 / plausible-network class traffic",
        "cat3.1": "Treated under CAT3.1 time/location correlation checks",
        "cat3.2": "Treated under CAT3.2 in-packet addressing correlation",
    }
    why_default = why_by_focus.get(focus_l, f"Enrolled under {focus}")

    for e in evidence or []:
        typ = str(e.get("type") or "")
        body = str(e.get("body") or "")
        src = str(e.get("source") or "")
        low = body.lower()
        if typ == "Message Policy":
            cat_ok = focus_l in low.replace(" ", "")
            if focus == "CAT1":
                cat_ok = "cat1" in low
            elif focus == "CAT2":
                cat_ok = "cat2" in low and "cat3" not in low
            elif focus == "CAT3":
                cat_ok = re.search(r"\bcat3\b", low) is not None
            elif focus == "CAT3.1":
                cat_ok = "cat3.1" in low or "3.1" in low
            elif focus == "CAT3.2":
                cat_ok = "cat3.2" in low or "3.2" in low
            if not cat_ok:
                continue
            msg = ""
            proto = ""
            fields = ""
            m = re.search(r"message=([^;]+)", body, re.I)
            if m:
                msg = m.group(1).strip()
            m = re.search(r"protocol=([^;]+)", body, re.I)
            if m:
                proto = m.group(1).strip()
            m = re.search(r"validation_fields=(.+)$", body, re.I)
            if m:
                fields = m.group(1).strip()
                fields = re.split(r";\s*[a-z_]+=", fields, maxsplit=1)[0].strip()
            if msg.upper() == "PROHIBITED" and fields:
                for part in re.split(r"[,;]", fields):
                    part = part.strip()
                    if not part or part.upper() in ("OPCODE", "COMMAND_CODE", "MESSAGE_TYPE"):
                        continue
                    rows.append((part, proto or "—", why_default))
            elif msg and msg.upper() != "PROHIBITED":
                rows.append((msg, proto or "—", f"Message policy category {focus}"))
        elif typ == "Document" and focus == "CAT1":
            # Prefer short concrete lines; skip TOC breadcrumbs.
            if body.count(">") >= 1 and re.search(r"^\d+\s+\S+", body.strip()):
                continue
            if re.search(r"should not be sent|points-of-interconnect|poi", low):
                excerpt = re.sub(r"\s+", " ", body).strip()
                if len(excerpt) > 40 and " > " not in excerpt[:80]:
                    bullets.append(f"FS extract ({src.split(' p.')[0][-40:] if src else 'spec'}): {excerpt[:220]}")
        elif typ == "Document" and focus in ("CAT3.1", "CAT3.2", "CAT3"):
            if re.search(r"origin-host|origin-realm|vplmn|velocity|ulr|air", low):
                excerpt = re.sub(r"\s+", " ", body).strip()
                if " > " not in excerpt[:80]:
                    bullets.append(f"Spec context: {excerpt[:220]}")

    # Deduplicate example rows
    seen: set[str] = set()
    uniq_rows: list[tuple[str, str, str]] = []
    for r in rows:
        if r[0].lower() in seen:
            continue
        seen.add(r[0].lower())
        uniq_rows.append(r)
        if len(uniq_rows) >= 6:
            break

    out: list[str] = []
    if uniq_rows:
        out += [
            "| Example | Protocol | Why it is listed here |",
            "| --- | --- | --- |",
        ]
        for msg, proto, why in uniq_rows:
            out.append(f"| {msg} | {proto} | {why} |")
    # Keep FS prose notes separate from the markdown table (caller folds into Related detail).
    for b in bullets[:2]:
        if b not in out:
            out.append(b)
    return out


def _split_category_examples(examples: list[str]) -> tuple[list[str], list[str]]:
    """Split example lines into a markdown table vs prose notes."""
    table: list[str] = []
    notes: list[str] = []
    for line in examples or []:
        s = (line or "").strip()
        if not s:
            continue
        if s.startswith("|"):
            table.append(s)
        else:
            # Strip leading "- " so Related detail can re-bullet uniformly.
            notes.append(re.sub(r"^[-•]\s*", "", s))
    return table, notes


def _dictionary_comparison_brief(query: str, evidence: list[dict]) -> str | None:
    q = (query or "").lower()
    want = []
    if re.search(r"3\.1", q) and re.search(r"3\.2", q):
        want = ["3.1", "3.2", "cat3.1", "cat3.2", "category-3.1", "category-3.2"]
    elif re.search(r"category[-\s]?2", q) and re.search(r"category[-\s]?3", q):
        want = ["cat2", "cat3", "category-2", "category-3", "category 2", "category 3"]

    if not want:
        return None

    picked: list[tuple[str, str]] = []
    seen: set[str] = set()
    # Prefer FS document prose over short dictionary glosses.
    for e in evidence:
        if e.get("type") != "Document":
            continue
        src = str(e.get("source") or "")
        body = str(e.get("body") or "").strip()
        blob = f"{src} {body}".lower()
        if not body or len(body) < 80:
            continue
        if not any(w in blob for w in want):
            continue
        key = body.lower()[:160]
        if key in seen:
            continue
        seen.add(key)
        picked.append((src or "standards", body[:1200]))

    for e in evidence:
        if e.get("type") != "Domain Dictionary":
            continue
        src = str(e.get("source") or "")
        body = str(e.get("body") or "").strip()
        blob = f"{src} {body}".lower()
        if not body:
            continue
        if not any(w in blob for w in want):
            continue
        key = body.lower()[:160]
        if key in seen:
            continue
        seen.add(key)
        picked.append((src or str(e.get("term") or "dictionary"), body))

    if len(picked) < 2 and re.search(r"3\.1", q):
        # Also pull from document chunks mentioning both subtypes
        for e in evidence:
            if e.get("type") not in ("Document", "Domain Dictionary"):
                continue
            body = str(e.get("body") or "")
            low = body.lower()
            if re.search(r"3\.1", low) and re.search(r"3\.2", low) and len(body) > 80:
                picked.append((str(e.get("source") or "standards"), body[:900]))
                break

    if len(picked) < 2:
        return None

    lines = ["## Summary (from domain dictionary / standards evidence)", ""]
    for src, body in picked[:4]:
        lines += [f"**{src}**", body, ""]
    body = "\n".join(lines[2:]).strip()
    return format_professional_brief(
        "Contrast the asked categories from enrolled dictionary and FS evidence below.",
        sections=[("Comparison", body)],
        source_rows=[
            ("Dictionary / FS", "Domain Dictionary + FS.xx extracts", "Comparison"),
        ],
    )


def _parameter_table_brief(query: str, evidence: list[dict]) -> str | None:
    from app.retrieval.table_chunk_search import build_lookup_answer
    from app.retrieval.context_builder import build_context

    # Message Policy rows already encode validation_fields for ULR/AIR/CSR.
    policy_brief = _policy_validation_brief(query, evidence)
    if policy_brief:
        return policy_brief

    # Prefer explicit table rows over dictionary glosses.
    table_ev = [e for e in (evidence or []) if e.get("type") == "Table"]
    if table_ev:
        ctx = build_context(table_ev[:8])
        brief = build_lookup_answer(query, ctx)
        if brief and not answer_mismatches_standards_query(query, brief):
            return brief

    std_ev = filter_standards_evidence(evidence)
    doc_ev = [e for e in std_ev if e.get("type") == "Document"]
    if doc_ev:
        ctx = build_context(doc_ev[:10])
        brief = build_lookup_answer(query, ctx)
        if brief and not answer_mismatches_standards_query(query, brief):
            return brief

    ctx = build_context(std_ev)
    brief = build_lookup_answer(query, ctx)
    if brief and not answer_mismatches_standards_query(query, brief):
        return brief

    # Collect explicit validation field mentions from document evidence
    qlow = (query or "").lower()
    keys = ("origin-host", "origin-realm", "imsi", "vplmn", "apn", "teid", "gt", "mcc", "mnc")
    if "ulr" in qlow or "update" in qlow and "location" in qlow:
        keys = ("origin-host", "origin-realm", "imsi", "vplmn", "316", "16777251", *keys)
    if "gtp" in qlow or "create session" in qlow:
        keys = ("imsi", "apn", "teid", "serving-network", "vplmn", "source-ip", *keys)

    hits: list[str] = []
    for e in list(evidence or []) + list(std_ev):
        body = str(e.get("body") or "")
        low = body.lower()
        if _ATTACK_TOPIC.search(low) and "parameter" not in low and "validat" not in low:
            continue
        for k in keys:
            if k in low and k not in hits:
                hits.append(k)
        for line in body.split("\n"):
            if re.search(r"\bvalidat", line.lower()) or re.search(r"\bparameter", line.lower()):
                line = line.strip()
                if 10 < len(line) < 220 and line not in hits:
                    hits.append(line)

    if len(hits) < 2:
        return None
    table = ["| Parameter / check | Source |", "| --- | --- |"]
    for h in hits[:12]:
        table.append(f"| {h} | FS / table evidence |")
    return format_professional_brief(
        "These parameters or checks appear in the retrieved standards evidence for this message.",
        sections=[("Parameters to validate", "\n".join(table))],
        source_rows=[("Standards extract", "FS.xx / table rows", "Parameters to validate")],
    )


def _policy_validation_brief(query: str, evidence: list[dict] | None) -> str | None:
    """Extract validation_fields from Message Policy evidence for parameter questions."""
    qlow = (query or "").lower()
    qnorm = qlow.replace("-", " ")
    if not re.search(r"\b(parameter|validat|ulr|air|create\s+session|update\s*location)\b", qlow):
        return None

    want_inbound = bool(re.search(r"\binbound\b", qlow))
    want_outbound = bool(re.search(r"\boutbound\b", qlow))
    want_ul = "ulr" in qlow or "update location" in qnorm or "updatelocation" in qnorm.replace(" ", "")

    # Collect matching policy rows (keep SS7 and Diameter separate — never merge fields).
    rows: list[dict[str, str]] = []
    for e in evidence or []:
        if e.get("type") not in ("Message Policy",) and e.get("agent") != "policy":
            continue
        body = str(e.get("body") or "")
        low = body.lower()
        if want_ul:
            if (
                "updatelocation" not in low.replace(" ", "")
                and "ulr" not in low
                and "316" not in low
            ):
                continue
        if "create session" in qlow and "createsession" not in low.replace(" ", "") and "gtp" not in low:
            continue
        if want_inbound and "direction=outbound" in low.replace(" ", ""):
            continue
        if want_outbound and "direction=inbound" in low.replace(" ", ""):
            continue

        fields_m = re.search(r"validation_fields=([^;\n]+)", body, re.I)
        if not fields_m:
            continue
        fields = [p.strip() for p in re.split(r"[,;/]", fields_m.group(1)) if p.strip()]
        if len(fields) < 2:
            continue
        pid = ""
        pm = re.search(r"policy_id=([^;\n]+)", body, re.I)
        if pm:
            pid = pm.group(1).strip()
        proto = ""
        prm = re.search(r"protocol=([^;\n]+)", body, re.I)
        if prm:
            proto = prm.group(1).strip()
        msg = ""
        mm = re.search(r"message=([^;\n]+)", body, re.I)
        if mm:
            msg = mm.group(1).strip()
        direction = ""
        dm = re.search(r"direction=([^;\n]+)", body, re.I)
        if dm:
            direction = dm.group(1).strip()
        action = ""
        am = re.search(r"action=([^;\n]+)", body, re.I)
        if am:
            action = am.group(1).strip()
        sig = ""
        sm = re.search(r"signature=([^;\n]+)", body, re.I)
        if sm:
            sig = sm.group(1).strip()
        rows.append(
            {
                "policy_id": pid,
                "protocol": proto,
                "message": msg,
                "direction": direction,
                "action": action,
                "signature": sig,
                "fields": ", ".join(fields),
            }
        )

    if not rows:
        return None

    # Prefer exact inbound matches when asked; keep at most one SS7 + one Diameter row.
    def _rank(r: dict[str, str]) -> tuple[int, int]:
        d = (r.get("direction") or "").upper()
        inbound_score = 0 if (want_inbound and d == "INBOUND") else 1
        return (inbound_score, 0 if "SS7" in (r.get("protocol") or "").upper() else 1)

    rows.sort(key=_rank)
    picked: list[dict[str, str]] = []
    seen_proto: set[str] = set()
    for r in rows:
        key = "SS7" if "SS7" in (r.get("protocol") or "").upper() else (
            "DIAMETER" if "DIAMETER" in (r.get("protocol") or "").upper() else r.get("protocol") or "?"
        )
        if key in seen_proto:
            continue
        seen_proto.add(key)
        picked.append(r)
        if len(picked) >= 2:
            break

    table = [
        "| Policy | Protocol | Message | Direction | Action | Validation fields |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in picked:
        table.append(
            f"| {r['policy_id'] or '—'} | {r['protocol'] or '—'} | {r['message'] or '—'} | "
            f"{r['direction'] or '—'} | {r['action'] or '—'} | {r['fields']} |"
        )
    notes_bits = [f"{r['policy_id']}: {r['signature']}" for r in picked if r.get("signature")]
    sections: list[tuple[str, str]] = [("Parameters to validate", "\n".join(table))]
    if notes_bits:
        sections.append(("Notes", "\n".join(f"- {n}" for n in notes_bits)))
    return format_professional_brief(
        "Validation parameters from enrolled inbound UpdateLocation / ULR message policy rows.",
        sections=sections,
        source_rows=[("Message policy", "validation_fields rows", "Parameters to validate")],
    )


def _normalize_message_name(name: str) -> str:
    raw = re.sub(r"\s+", " ", (name or "").strip())
    low = raw.lower()
    canon = {
        "create session": "Create Session Request",
        "create session request": "Create Session Request",
        "create session response": "Create Session Response",
        "delete session": "Delete Session Request",
        "delete session request": "Delete Session Request",
        "modify bearer": "Modify Bearer Request",
        "modify bearer request": "Modify Bearer Request",
        "create pdp": "Create PDP Context Request",
        "create pdp context": "Create PDP Context Request",
        "update pdp": "Update PDP Context Request",
        "update pdp context": "Update PDP Context Request",
        "delete pdp": "Delete PDP Context Request",
        "delete pdp context": "Delete PDP Context Request",
        "echo request": "Echo Request",
        "echo response": "Echo Response",
        "ulr": "ULR (Update-Location-Request)",
        "ula": "ULA (Update-Location-Answer)",
        "air": "AIR (Authentication-Information-Request)",
        "aia": "AIA (Authentication-Information-Answer)",
        "clr": "CLR (Cancel-Location-Request)",
        "cla": "CLA (Cancel-Location-Answer)",
    }
    if low in canon:
        return canon[low]
    if len(raw) <= 4:
        return raw.upper()
    return raw.title() if raw.islower() else raw


def _dedupe_messages(msgs: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in msgs:
        norm = _normalize_message_name(m)
        key = re.sub(r"[^a-z0-9]+", "", norm.lower())
        # Drop shorter duplicates already covered (Create Session ⊂ Create Session Request).
        if any(key in s or s in key for s in seen if min(len(key), len(s)) >= 8):
            # Prefer the longer canonical form.
            for i, prev in enumerate(out):
                pk = re.sub(r"[^a-z0-9]+", "", prev.lower())
                if key in pk or pk in key:
                    if len(norm) > len(prev):
                        out[i] = norm
                        seen.discard(pk)
                        seen.add(key)
                    break
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(norm)
    return out


def _message_list_brief(query: str, evidence: list[dict]) -> str | None:
    qlow = (query or "").lower()
    msgs: list[str] = []
    for e in filter_standards_evidence(evidence):
        body = str(e.get("body") or "")
        low = body.lower()
        if _ATTACK_TOPIC.search(low) and not _MSG_ABBREV.search(body):
            continue
        for m in _MSG_ABBREV.findall(body):
            msgs.append(m)
        for m in re.findall(
            r"\b(Update-Location|Authentication-Information|Cancel-Location|"
            r"Insert-Subscriber|Create\s*Session(?:\s*Request|\s*Response)?|"
            r"Delete\s*Session(?:\s*Request|\s*Response)?|Modify\s*Bearer(?:\s*Request)?|"
            r"Create\s*PDP(?:\s*Context)?|Update\s*PDP(?:\s*Context)?|"
            r"Delete\s*PDP(?:\s*Context)?|Echo\s*Request|Echo\s*Response|"
            r"SendAuthenticationInfo|ProvideSubscriberInfo|AnyTimeInterrogation|"
            r"UpdateLocation|InsertSubscriberData)[^\n]{0,40}",
            body,
            re.I,
        ):
            msgs.append(m.strip())
    msgs = _dedupe_messages(msgs)
    if "authentication" in qlow or ("location" in qlow and "gtp" not in qlow):
        preferred = [
            m for m in msgs
            if re.search(r"\b(ulr|ula|air|aia|clr|cla|update-location|authentication-information)\b", m, re.I)
        ]
        if preferred:
            msgs = preferred + [m for m in msgs if m not in preferred]
    if "gtp" in qlow or ("session" in qlow and "diameter" not in qlow):
        preferred = [
            m for m in msgs
            if re.search(r"create\s*session|create\s*pdp|modify\s*bearer|delete\s*session", m, re.I)
        ]
        if preferred:
            msgs = preferred + [m for m in msgs if m not in preferred]
    if "ss7" in qlow or "map" in qlow:
        preferred = [
            m for m in msgs
            if re.search(
                r"sendauthentication|providesubscriber|anytimeinterrogation|updatelocation|insertsubscriber",
                m,
                re.I,
            )
        ]
        if preferred:
            msgs = preferred + [m for m in msgs if m not in preferred]
    if len(msgs) < 2:
        # No hardcoded message seed lists — only report what retrieval actually found.
        return None
    has_fs20 = any("fs.20" in str(e.get("source") or "").lower() for e in (evidence or []))
    has_fs19 = any("fs.19" in str(e.get("source") or "").lower() for e in (evidence or []))
    has_fs11 = any("fs.11" in str(e.get("source") or "").lower() for e in (evidence or []))
    table = ["| Message | Source |", "| --- | --- |"]
    for m in msgs[:12]:
        table.append(f"| {m} | FS / policy evidence |")
    focus = ""
    if has_fs20 and ("gtp" in qlow or "session" in qlow):
        focus = "GSMA FS.20 (GTP Security)"
    elif has_fs19 and "diameter" in qlow:
        focus = "GSMA FS.19 (Diameter Interconnect Security)"
    elif has_fs11 and ("ss7" in qlow or "map" in qlow or "prohibit" in qlow):
        focus = "GSMA FS.11 (SS7 Interconnect Security)"
    sections: list[tuple[str, str]] = [("Associated messages", "\n".join(table))]
    if focus:
        sections.append(("Notes", f"Primary document focus: {focus}"))
    return format_professional_brief(
        "Messages associated with this protocol/category in retrieved evidence.",
        sections=sections,
        source_rows=[("Standards / policy", focus or "FS.xx extracts", "Associated messages")],
    )


def _mcc_mnc_reason_brief(query: str, evidence: list[dict]) -> str | None:
    lines = ["## Why MCC/MNC equality is insufficient (from standards evidence)", ""]
    found = 0
    for e in filter_standards_evidence(evidence):
        body = str(e.get("body") or "")
        low = body.lower()
        if not re.search(r"\bmcc\b|\bmnc\b", low):
            continue
        if _ATTACK_TOPIC.search(low) and "partner" not in low and "agreement" not in low:
            continue
        for para in re.split(r"\n{2,}", body):
            plow = para.lower()
            if re.search(r"\bmcc\b|\bmnc\b", plow) and any(
                t in plow for t in ("partner", "agreement", "spoof", "identity", "plmn", "insufficient", "not sufficient")
            ):
                lines.append(para.strip()[:700])
                found += 1
    return "\n".join(lines).strip() if found else None


def _prohibited_messages_brief(query: str, evidence: list[dict]) -> str | None:
    """Policy-led prohibited message list — never paste raw FS rule dumps."""
    qlow = (query or "").lower()
    want_ss7 = "ss7" in qlow or "map" in qlow

    enriched = list(evidence or [])
    if not any(e.get("type") == "Message Policy" for e in enriched):
        try:
            from app.ontology.policy_knowledge import search_policy

            pol = search_policy(query) or {}
            for row in (pol.get("evidence") or [])[:6]:
                if row.get("type") == "Message Policy":
                    enriched.append(row)
        except Exception:
            pass

    example_lines = _category_examples_from_evidence("CAT1", enriched)
    example_table, _ = _split_category_examples(example_lines)
    if not example_table and want_ss7:
        # Extract MAP message names from policy rows only (not FS prose).
        rows: list[tuple[str, str, str]] = []
        for e in enriched:
            if e.get("type") != "Message Policy":
                continue
            body = str(e.get("body") or "")
            if "cat1" not in body.lower():
                continue
            proto = ""
            m = re.search(r"protocol=([^;]+)", body, re.I)
            if m:
                proto = m.group(1).strip()
            m = re.search(r"validation_fields=(.+)$", body, re.I)
            if not m:
                continue
            fields = re.split(r";\s*[a-z_]+=", m.group(1).strip(), maxsplit=1)[0]
            for part in re.split(r"[,;]", fields):
                part = part.strip()
                if not part or part.upper() in ("OPCODE", "COMMAND_CODE", "MESSAGE_TYPE"):
                    continue
                rows.append((part, proto or "SS7/MAP", "CAT1 — interface-unauthorised / BLOCK"))
        seen: set[str] = set()
        if rows:
            example_table = ["| Message | Protocol | Category / action |", "| --- | --- | --- |"]
            for msg, proto, why in rows:
                if msg.lower() in seen:
                    continue
                seen.add(msg.lower())
                example_table.append(f"| {msg} | {proto} | {why} |")
                if len(seen) >= 10:
                    break

    if not example_table:
        return None

    lead = (
        "CAT1 (interface-unauthorised) signalling messages are **blocked** on the international "
        "roaming interconnect unless a bilateral agreement explicitly allows them."
    )
    if want_ss7:
        lead = (
            "On an SS7/MAP international roaming interconnect, CAT1 messages are **prohibited** "
            "(BLOCK) — they should not be received from a partner network at the POI."
        )

    return format_professional_brief(
        lead,
        sections=[("Prohibited / restricted messages", "\n".join(example_table))],
        source_rows=[
            ("Message policy", "CAT1 PROHIBITED / validation_fields", "Prohibited messages"),
            ("Standards", "FS.11 §B.3 / FS.21 §7.2.1", "Answer"),
        ],
    )


def _best_standards_brief(
    query: str,
    context: str,
    evidence: list[dict] | None,
    *,
    table_brief: str | None = None,
) -> str | None:
    """Pick the best grounded brief for a standards-led question.

    Prefer prose / evidence synthesis over thin field-lookup tables so answers
    are formal content, not ``Reference = 3GPP TS …`` dumps.
    """
    candidates: list[str] = []
    prose = standards_prose_brief(query, context)
    if prose:
        candidates.append(prose)
    ev_brief = standards_evidence_brief(query, evidence)
    if ev_brief:
        candidates.append(ev_brief)
    if table_brief and not is_rule_dump_answer(table_brief):
        low = table_brief.lower()
        if "| chunk_id |" not in low and "**chunk_id**" not in low:
            # Citation-only tables last, and only when the query asks for a reference.
            q = (query or "").lower()
            wants_ref = bool(
                re.search(r"\breference\b|\b3gpp\s*ts\b|\bts\s*29\b|\bcite\b", q)
            )
            if wants_ref or "documented values" not in low:
                candidates.append(table_brief)
            elif not re.search(r"documents\s+\*?\*?reference\*?\*?\s*=", low):
                candidates.append(table_brief)
    for brief in candidates:
        if brief and not answer_mismatches_standards_query(query, brief):
            return brief
    return candidates[0] if candidates else None


def standards_prose_brief(query: str, context: str) -> str | None:
    """Build a grounded brief from FS/dictionary prose when table lookup is unavailable."""
    if not (query and context):
        return None

    blocks: list[tuple[float, str, str, str]] = []
    for m in _SOURCE_BLOCK.finditer(context):
        etype = m.group(2).strip()
        source = m.group(3).strip()
        start = m.end()
        nxt = _SOURCE_BLOCK.search(context, start)
        body = (context[start : nxt.start()] if nxt else context[start:]).strip()
        if not body:
            continue
        if _TOOL_DOC_MARKERS.search(body) and "fs." not in body.lower():
            continue
        score = _score_block(query, body, source, etype)
        if score >= 1.0:
            blocks.append((score, etype, source, body))

    if not blocks:
        return None

    q = (query or "").lower()
    if re.search(r"3\.1", q) and re.search(r"3\.2", q):
        left = [b for b in blocks if re.search(r"3\.1", b[3].lower()) or "cat3.1" in b[2].lower()]
        right = [b for b in blocks if re.search(r"3\.2", b[3].lower()) or "cat3.2" in b[2].lower()]
        picked: list[tuple[float, str, str, str]] = []
        if left:
            picked.append(max(left, key=lambda x: x[0]))
        if right:
            picked.append(max(right, key=lambda x: x[0]))
        if len(picked) >= 2:
            blocks = picked
        else:
            blocks = sorted(blocks, key=lambda x: -x[0])[:3]
    else:
        blocks = sorted(blocks, key=lambda x: -x[0])[:3]

    def _short_source(source: str) -> str:
        src = (source or "").strip()
        m = re.search(r"((?:FS|IR)\.[0-9]+[^/\n]*\.pdf)", src, re.I)
        return m.group(1) if m else src

    # Definition / "what is" asks: lead with a single clean Answer from the best block.
    if re.search(r"\bwhat\s+is\b|\bdefine\b|\bdefinition\b|\bmean(?:s|ing)?\b", q):
        score, etype, source, body = blocks[0]
        excerpt = body.strip()
        if len(excerpt) > 1600:
            excerpt = excerpt[:1600].rsplit(" ", 1)[0] + "…"
        return "\n".join(
            [
                "## Answer",
                "",
                excerpt,
                "",
                "## Details",
                "",
                "Operational takeaway: treat the definition above as the interconnect control "
                "baseline and enforce it against inbound/outbound signalling policy.",
            ]
        ).strip()

    lines = ["## Answer", ""]
    for _, etype, source, body in blocks:
        excerpt = body.strip()
        if len(excerpt) > 2200:
            excerpt = excerpt[:2200].rsplit(" ", 1)[0] + "…"
        lines.append(excerpt)
        lines.append("")
    return "\n".join(lines).strip() if len(lines) > 2 else None


def filter_standards_evidence(evidence: list[dict]) -> list[dict]:
    """Keep only FS standards / dictionary prose — drop tools, IDS, Suricata chunks."""
    out: list[dict] = []
    for e in evidence:
        agent = str(e.get("agent") or "")
        if agent and agent not in ("standards", "dictionary"):
            continue
        typ = str(e.get("type") or "")
        if typ in ("Tool Knowledge", "Threat Knowledge", "IDS"):
            continue
        if typ == "Table":
            out.append(e)
            continue
        blob = " ".join(
            str(e.get(k) or "")
            for k in ("source", "file_name", "body", "store")
        ).lower()
        if _TOOL_DOC_MARKERS.search(blob):
            continue
        out.append(e)
    return out


def filter_standards_context(context: str, query: str = "") -> str:
    """Drop Suricata / tool / attack-scenario lines from assembled context for theory questions."""
    if not context:
        return ""
    q = (query or "").lower()
    drop_attacks = bool(
        re.search(r"\bparameters?\b", q)
        or re.search(r"\bvalidat", q)
        or re.search(r"\bdifference\b", q)
        or re.search(r"\bwhat\s+is\b", q)
        or re.search(r"\bwhich\b.*\bmessages?\b", q)
        or re.search(r"\bwhy\b", q)
    )
    # Keep whole SOURCE blocks intact — splitting on blank lines shreds multi-paragraph evidence.
    if re.search(r"(?m)^SOURCE\s+\d+", context):
        chunks = [c.strip() for c in re.split(r"(?=^SOURCE\s+\d+\b)", context, flags=re.M) if c.strip()]
    else:
        chunks = [c.strip() for c in re.split(r"\n{2,}", context) if c.strip()]
    kept: list[str] = []
    for block in chunks:
        low = block.lower()
        if _TOOL_DOC_MARKERS.search(low) and "fs." not in low and "gsma" not in low:
            continue
        if low.strip().startswith("## detection rule"):
            continue
        if drop_attacks and _ATTACK_TOPIC.search(low):
            if not re.search(r"\bparameter|validat|whitelist|filter", low):
                continue
        kept.append(block)
    return "\n\n".join(kept)


def answer_mismatches_standards_query(query: str, answer: str) -> bool:
    """True when synthesis clearly answered the wrong question."""
    q = (query or "").lower()
    a = (answer or "").lower()
    if not a.strip():
        return True
    if is_rule_dump_answer(answer) and not wants_detection_answer(query):
        return True
    if re.search(r"3\.1|cat[-\s]?3\.1", q) and re.search(r"3\.2|cat[-\s]?3\.2", q):
        if not re.search(r"3\.1", a) or not re.search(r"3\.2", a):
            return True
        if re.search(r"category\s*2|cat\s*2", a) and not re.search(r"3\.1", a):
            return True
    if re.search(r"difference\s+between\s+category[-\s]?2\s+and\s+category[-\s]?3", q):
        has2 = bool(re.search(r"category\s*2|cat\s*2|cat2", a))
        has3 = bool(re.search(r"category\s*3|cat\s*3|cat3", a))
        if has2 and not has3:
            return True
        if re.search(r"category\s*2", a) and re.search(r"category\s*3\.1", q):
            return False
    if re.search(r"\bwhich\b", q) and re.search(r"\bmessages?\b", q):
        if _ATTACK_TOPIC.search(a) and not _MSG_ABBREV.search(a):
            return True
        if "attack scenario" in a and "countermeasure" in a:
            return True
    if re.search(r"\bparameters?\b", q) and re.search(r"\bvalidat", q):
        if "inbound roamer protection" in a and not re.search(
            r"\bparameter|origin-host|origin-realm|imsi|apn|teid|gt\b", a
        ):
            return True
        if re.search(r"\bdos\s+attack\b", a) and not re.search(
            r"\bshould\s+be\s+validat|parameters?\s+to\s+validat|validation\s+field", a
        ):
            return True
        if _ATTACK_TOPIC.search(a) and not re.search(r"\bparameter|origin-host|origin-realm|imsi|apn|teid", a):
            return True
    if re.search(r"\bmcc\b|\bmnc\b", q):
        if not re.search(r"\bmcc\b|\bmnc\b", a):
            return True
    if re.search(r"\bprohibit", q) or re.search(r"\bforbidden\b", q):
        if not re.search(r"\bprohibit|forbidden|never|block|unauthor", a):
            return True
    if q.startswith("why ") and len(a) < 120 and is_rule_dump_answer(answer):
        return True
    return False
