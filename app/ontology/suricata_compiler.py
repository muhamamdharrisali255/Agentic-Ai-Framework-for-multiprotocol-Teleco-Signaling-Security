"""Compile / validate Suricata text from detection_rule rows (§7).

Never invents unpublished signatures — only formats or checks enrolled text.
"""

from __future__ import annotations

import re
from typing import Any

_RULE_LINE = re.compile(
    r"^(alert|drop|reject|pass)\s+\S+\s+\S+\s+\S+\s+->\s+\S+\s+\S+\s*\(.*\)$",
    re.I,
)
_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.I)
_REV = re.compile(r"\brev\s*:\s*(\d+)\s*;", re.I)
_MSG = re.compile(r'\bmsg\s*:\s*"([^"]+)"\s*;', re.I)
_RULE_INLINE = re.compile(
    r"(alert|drop|reject|pass)\s+\S+\s+\S+\s+\S+\s+->\s+\S+\s+\S+\s*\([^)]+\)",
    re.I,
)
_FENCED_SURICATA = re.compile(r"```(?:suricata|rules?)?\s*\n([^`]+)```", re.I | re.S)


def compile_rule(row: dict[str, Any]) -> dict[str, Any]:
    """Return validated Suricata text for a detection_rule row."""
    text = (row.get("suricata_text") or "").strip()
    rule_id = str(row.get("detection_rule_id") or "")
    name = str(row.get("rule_name") or rule_id or "TEL-RULE")
    action = str(row.get("action") or "ALERT").upper()
    sid = _sid_for(rule_id)

    if text:
        ok = bool(_RULE_LINE.match(text.replace("\n", " ").strip()))
        if not ok:
            # Soft-normalize common enrolled forms.
            text = _normalize(text, name=name, action=action, sid=sid)
            ok = bool(_RULE_LINE.match(text))
        # BLOCK policy must emit Suricata drop (not alert).
        text = _apply_action_keyword(text, action)
        ok = bool(_RULE_LINE.match(text.replace("\n", " ").strip()))
        return {
            "detection_rule_id": rule_id,
            "suricata_text": text,
            "valid": ok,
            "sid": (_SID.search(text).group(1) if _SID.search(text) else str(sid)),
            "action": action,
            "invented": False,
        }

    # No enrolled text — emit a placeholder shell tagged TESTING only.
    # Callers must not promote this to PRODUCTION without analyst review.
    kw = _action_keyword(action)
    shell = (
        f'{kw} ip any any -> any any (msg:"{name}"; '
        f"sid:{sid}; rev:1; classtype:trojan-activity;)"
    )
    return {
        "detection_rule_id": rule_id,
        "suricata_text": shell,
        "valid": True,
        "sid": str(sid),
        "action": action,
        "invented": False,
        "placeholder": True,
        "note": "No suricata_text enrolled; placeholder shell for TESTING only.",
    }


def compile_all(*, status: str | None = "PRODUCTION") -> list[dict[str, Any]]:
    try:
        from app.database import postgres
    except Exception:
        return []
    if not postgres.is_available():
        return []
    sql = "SELECT * FROM detection_rule WHERE 1=1"
    params: tuple = ()
    if status:
        sql += " AND status = %s"
        params = (status,)
    sql += " ORDER BY detection_rule_id"
    rows = postgres.fetch_all(sql, params)
    return [compile_rule(dict(r)) for r in rows]


def _sid_for(rule_id: str) -> int:
    m = re.search(r"(\d+)$", rule_id or "")
    n = int(m.group(1)) if m else 1
    return 900000 + n


def _normalize(text: str, *, name: str, action: str, sid: int) -> str:
    line = " ".join(text.split())
    if _RULE_LINE.match(line):
        return line
    if not _MSG.search(line):
        line = f'alert ip any any -> any any (msg:"{name}"; sid:{sid}; rev:1;)'
    return line


def _action_keyword(action: str) -> str:
    return "drop" if str(action or "").upper() == "BLOCK" else "alert"


def _apply_action_keyword(text: str, action: str) -> str:
    """Force Suricata action keyword to match policy (BLOCK→drop, else alert)."""
    line = " ".join((text or "").split())
    if not line:
        return line
    kw = _action_keyword(action)
    return re.sub(r"^(alert|drop|reject|pass)\b", kw, line, count=1, flags=re.I)


def validate_rule_line(text: str) -> dict[str, Any]:
    """Validate a single Suricata rule line."""
    line = " ".join((text or "").replace("\n", " ").split())
    issues: list[str] = []
    if not line:
        return {"valid": False, "line": "", "issues": ["empty rule"]}
    if not _RULE_LINE.match(line):
        issues.append("header must match: action proto src src_port -> dst dst_port (options;)")
    if not _MSG.search(line):
        issues.append("missing msg:\"...\";")
    if not _SID.search(line):
        issues.append("missing sid:N;")
    if not _REV.search(line):
        issues.append("missing rev:N;")
    if line.count("(") != line.count(")"):
        issues.append("unbalanced parentheses")
    sid_m = _SID.search(line)
    msg_m = _MSG.search(line)
    return {
        "valid": not issues,
        "line": line,
        "sid": sid_m.group(1) if sid_m else None,
        "msg": msg_m.group(1) if msg_m else None,
        "issues": issues,
    }


def extract_rules_from_text(text: str) -> list[str]:
    """Pull Suricata rule lines from markdown / prose."""
    found: list[str] = []
    seen: set[str] = set()
    for block in _FENCED_SURICATA.findall(text or ""):
        for raw in block.splitlines():
            line = " ".join(raw.split())
            if _RULE_INLINE.search(line):
                norm = validate_rule_line(line)["line"]
                if norm and norm not in seen:
                    seen.add(norm)
                    found.append(norm)
    for m in _RULE_INLINE.finditer(text or ""):
        norm = validate_rule_line(m.group(0))["line"]
        if norm and norm not in seen:
            seen.add(norm)
            found.append(norm)
    return found


def _rule_from_detection_row(row: dict[str, Any]) -> str | None:
    compiled = compile_rule(row)
    line = str(compiled.get("suricata_text") or "").strip()
    if line and validate_rule_line(line)["valid"]:
        action = _action_keyword(str(row.get("action") or ""))
        if action == "drop" and line.lower().startswith("alert "):
            line = "drop " + line[6:]
        return line
    return None


def _best_rule_from_context(context: str) -> str | None:
    rules = extract_rules_from_text(context or "")
    for line in rules:
        if validate_rule_line(line)["valid"]:
            return line
    return None


def ensure_rule_draft_answer(
    answer: str,
    *,
    context: str = "",
    detection_rules: list[dict[str, Any]] | None = None,
) -> str:
    """Ensure a rule-draft answer contains at least one valid Suricata rule line."""
    text = (answer or "").strip()
    valid = [r for r in extract_rules_from_text(text) if validate_rule_line(r)["valid"]]

    fallback: str | None = None
    if not valid:
        for row in detection_rules or []:
            fallback = _rule_from_detection_row(row)
            if fallback:
                break
    if not fallback:
        fallback = _best_rule_from_context(context)

    if not valid and not fallback:
        note = (
            "\n\n> **Note:** No syntactically valid Suricata rule was produced. "
            "A complete rule must look like: "
            "`drop tcp any any -> any 3868 (msg:\"TEL-RULE\"; sid:900002; rev:1; "
            "classtype:policy-violation;)`"
        )
        return text + note if text else note.strip()

    rule_line = valid[0] if valid else fallback
    if not rule_line:
        return text

    fence = f"```suricata\n{rule_line}\n```"
    if fence in text or rule_line in text:
        return text

    if re.search(r"(?im)^##\s*detection\s+rule", text):
        return re.sub(
            r"(?im)^##\s*detection\s+rule\s*\n",
            f"## Detection rule\n\n{fence}\n\n",
            text,
            count=1,
        )
    return f"## Detection rule\n\n{fence}\n\n{text}"
