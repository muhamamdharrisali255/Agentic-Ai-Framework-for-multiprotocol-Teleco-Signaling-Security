"""Deprecated compatibility shim — use shared.llm instead."""

from __future__ import annotations

from shared.llm import (
    _load_local,
    answer_question,
    answer_question_raw,
    is_llm_available,
    preload_llm,
    rewrite_query_for_search,
)

# Deprecated aliases
is_gemma_available = is_llm_available
preload_gemma = preload_llm

__all__ = [
    "answer_question",
    "answer_question_raw",
    "rewrite_query_for_search",
    "is_llm_available",
    "preload_llm",
    "is_gemma_available",
    "preload_gemma",
    "_load_local",
]
