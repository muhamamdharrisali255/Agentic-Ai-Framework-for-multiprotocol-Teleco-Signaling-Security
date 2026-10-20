#!/usr/bin/env python3
"""Single reproduction entry point for the research artifact.

Validates benchmark questionnaires and core CAT / answer-shape logic.
No API keys or model weights required.

  python test/reproduce.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

QUESTIONNAIRE = ROOT / "evaluation" / "questionnaire_250.json"


def load_questionnaire(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "questions" not in data:
        raise ValueError(f"{path.name}: expected object with 'questions'")
    return data


def check_questionnaire(data: dict) -> None:
    questions = data["questions"]
    assert questions, "questionnaire is empty"
    ids = [q.get("id") for q in questions]
    assert all(ids), "every question needs an id"
    assert len(ids) == len(set(ids)), f"duplicate ids: {Counter(ids)}"
    assert all((q.get("question") or "").strip() for q in questions), "empty question text"
    cats = {q.get("category") for q in questions}
    assert all(cats), "every question needs a category"
    assert len(questions) == 250, f"expected 250 questions, got {len(questions)}"
    print(f"  questionnaire OK — {len(questions)} questions, {len(cats)} categories")


def check_answer_shapes() -> None:
    from app.agent.query_intent import AnswerShape, detect_answer_shape

    fixtures = [
        ("What is a Category-1 signaling message?", AnswerShape.DEFINITION),
        (
            "Which GTP-C messages are relevant to roaming session establishment?",
            AnswerShape.ENUMERATION,
        ),
        (
            "What parameters should be validated for a Diameter ULR?",
            AnswerShape.PARAMETERS,
        ),
    ]
    for text, expected in fixtures:
        got = detect_answer_shape(text)
        assert got == expected, f"shape({text!r}) -> {got}, expected {expected}"
    print(f"  answer-shape fixtures OK — {len(fixtures)} cases")


def check_category_router_import() -> None:
    from app.ids.category_router import CategoryRouter
    from app.ids.decision import Category, DecisionType

    assert CategoryRouter is not None
    assert Category.CAT1 and DecisionType.ALLOW
    print("  IDS category stack import OK (CAT1/CAT2/CAT3)")


def main() -> int:
    print("Reproduce — Knowledge-Grounded Agentic AI for Multi-Protocol Signaling Security\n")
    try:
        data = load_questionnaire(QUESTIONNAIRE)
        check_questionnaire(data)
        check_answer_shapes()
        check_category_router_import()
    except Exception as exc:
        print(f"\nFAIL: {exc}")
        return 1
    print("\nPASS — reproduction checks succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
