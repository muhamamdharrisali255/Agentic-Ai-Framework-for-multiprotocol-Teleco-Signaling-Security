"""Local instruction LLM — OTel-LLM-E4B-IT (bf16) or Qwen2.5 fallback on GPU, HTTP API, or stub.

Embeddings use OTel-Embedding-300M (shared.embeddings).
Configure via LLM_MODEL_PATH, LLM_MODEL, LLM_BASE_URL, TEMPERATURE.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from functools import lru_cache
from pathlib import Path

import config

# Optional callback set by SSE handlers so tokens reach the UI while generating.
# reset_cb clears the streamed buffer before a new generation (retry / fallback).
_stream_cb_local = threading.local()


def set_token_callback(
    cb: Callable[[str], None] | None,
    *,
    reset_cb: Callable[[], None] | None = None,
) -> None:
    _stream_cb_local.cb = cb
    _stream_cb_local.reset_cb = reset_cb


def get_token_callback() -> Callable[[str], None] | None:
    return getattr(_stream_cb_local, "cb", None)


def _emit_token(text: str) -> None:
    cb = get_token_callback()
    if cb and text:
        try:
            cb(text)
        except Exception:
            pass


def _emit_stream_reset() -> None:
    """Clear UI streamed text before starting another generation."""
    reset_cb = getattr(_stream_cb_local, "reset_cb", None)
    if reset_cb:
        try:
            reset_cb()
        except Exception:
            pass


def _is_otel_llm() -> bool:
    blob = f"{config.LLM_MODEL} {config.LLM_MODEL_PATH}".lower()
    return "otel" in blob and "llm" in blob


def _build_prompt_user(
    question: str,
    context: str,
    *,
    style: str = "professional",
    history: list[dict[str, str]] | None = None,
) -> str:
    from app.agent.query_intent import format_directive_for_query, format_suricata_rule_directive
    from app.llm.prompts import (
        GROUNDING_RULES,
        HYBRID_ANSWER_PROMPT,
        OTEL_RAG_PROMPT,
        PROFESSIONAL_ANSWER_PROMPT,
        RECORD_LOOKUP_PROMPT,
        RULE_DRAFT_PROMPT,
        SECURITY_INTELLIGENCE_PROMPT,
        format_otel_contexts,
    )

    format_directive = (
        format_suricata_rule_directive(question)
        if style == "rule_draft"
        else format_directive_for_query(question)
    )

    # OTel-LLM is fine-tuned on a fixed raw RAG layout (see model card).
    if _is_otel_llm() and style not in ("rule_draft", "security_intelligence"):
        hist = _format_history(history)
        q = question
        if hist:
            q = f"{hist}\n{question}"
        return OTEL_RAG_PROMPT.format(
            question=q.strip(),
            context=format_otel_contexts(context),
            format_directive=format_directive,
        )

    history_block = _format_history(history)
    grounding = GROUNDING_RULES
    fmt = dict(
        context=context,
        question=question,
        history=history_block,
        grounding=grounding,
        format_directive=format_directive,
    )

    if style == "hybrid":
        return HYBRID_ANSWER_PROMPT.format(**fmt)
    if style == "record_lookup":
        return RECORD_LOOKUP_PROMPT.format(**fmt)
    if style == "rule_draft":
        return RULE_DRAFT_PROMPT.format(**fmt)
    if style == "security_intelligence":
        return SECURITY_INTELLIGENCE_PROMPT.format(**fmt)
    # All other styles (brief, adaptive, expand, structured_lookup, table_lookup, professional)
    return PROFESSIONAL_ANSWER_PROMPT.format(**fmt)


def answer_question(
    question: str,
    context: str,
    *,
    style: str = "professional",
    history: list[dict[str, str]] | None = None,
    max_tokens: int | None = None,
    stream: bool = True,
) -> str:
    """Generate an answer from retrieved context.

    When ``stream=False``, tokens are not pushed to the SSE callback — callers
    can validate the full answer and emit only an accepted final string.
    """
    prompt_user = _build_prompt_user(question, context, style=style, history=history)
    tokens = max_tokens or config.MAX_NEW_TOKENS
    if config.LLM_BASE_URL:
        text = _answer_via_http(prompt_user, max_tokens=tokens)
        if stream:
            _emit_token(text)
        return text
    if config.LLM_USE_LOCAL and config.LLM_MODEL_PATH:
        if stream and get_token_callback():
            return "".join(_iter_local_tokens(prompt_user, max_tokens=tokens))
        return _answer_via_local(prompt_user, max_tokens=tokens, emit=stream)
    stub = _answer_stub(question, context)
    if stream:
        _emit_token(stub)
    return stub


def _format_history(history: list[dict[str, str]] | None) -> str:
    if not history:
        return ""
    lines = []
    for turn in history[-8:]:
        role = (turn.get("role") or "user").capitalize()
        content = (turn.get("content") or "").strip()
        if content:
            if len(content) > 700:
                content = content[:700] + "…"
            lines.append(f"{role}: {content}")
    if not lines:
        return ""
    return "[Prior conversation]\n" + "\n".join(lines) + "\n[/Prior conversation]\n\n"


def rewrite_query_for_search(query: str) -> str:
    """General query rewrite for better retrieval — does not answer the question."""
    q = (query or "").strip()
    if not q or not is_llm_available():
        return q
    prompt = (
        "Rewrite this document search query to improve retrieval.\n"
        "Goals:\n"
        "- Fix clear typos; keep ambiguous acronyms as written\n"
        "- Expand value-type shorthand only when it helps search\n"
        "- Keep user intent; do NOT answer\n"
        "- One short line; output ONLY the rewritten query\n\n"
        f"Query: {q}\n\nRewritten:"
    )
    try:
        out = answer_question_raw(prompt, max_tokens=48).strip().strip('"').strip("'")
        if not out or len(out) > 240:
            return q
        if out.lower().startswith(("the ", "based on", "according", "i ", "here")):
            return q
        return out
    except Exception:
        return q


def _answer_via_http(prompt: str, *, max_tokens: int | None = None) -> str:
    import requests

    url = f"{config.LLM_BASE_URL}/api/generate"
    payload = {
        "model": config.LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": config.TEMPERATURE,
            "num_predict": max_tokens or config.MAX_NEW_TOKENS,
        },
    }
    try:
        resp = requests.post(url, json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", str(data))
    except Exception as exc:
        return f"[LLM HTTP error: {exc}]"


def _system_prompt() -> str:
    """Always read current SYSTEM_PROMPT (supports reload without process restart)."""
    from app.llm.prompts import SYSTEM_PROMPT

    return SYSTEM_PROMPT


def llm_model_source() -> str:
    path = Path(config.LLM_MODEL_PATH) if config.LLM_MODEL_PATH else None
    if path and path.joinpath("config.json").exists():
        return str(path)
    return config.LLM_MODEL or ""


def _model_source() -> str:
    return llm_model_source()


def _resolve_max_input_tokens(tokenizer, source: str) -> int:
    """Prefer env/config cap; never trust a tiny tokenizer model_max_length (OTel ships 1500)."""
    configured = int(getattr(config, "LLM_MAX_INPUT_TOKENS", 0) or 0)
    model_cap = 0
    try:
        import json

        cfg_path = Path(source) / "config.json"
        if cfg_path.exists():
            raw = json.loads(cfg_path.read_text())
            text_cfg = raw.get("text_config") or {}
            model_cap = int(
                text_cfg.get("max_position_embeddings")
                or raw.get("max_position_embeddings")
                or 0
            )
    except Exception:
        model_cap = 0
    tok_cap = int(getattr(tokenizer, "model_max_length", 0) or 0)
    # HuggingFace sometimes sets a huge sentinel; treat > 1e6 as unset.
    if tok_cap > 1_000_000:
        tok_cap = 0
    # Ignore obviously wrong tiny tokenizer caps (e.g. OTel 1500) when the model is larger.
    if tok_cap and model_cap and tok_cap < 4096 and model_cap >= 4096:
        tok_cap = 0
    candidates = [c for c in (configured, model_cap, tok_cap) if c and c > 0]
    if not candidates:
        return configured or 8192
    # Use configured if set; otherwise the smallest sane positive cap.
    if configured > 0:
        upper = min([c for c in (model_cap, configured) if c > 0] or [configured])
        return min(configured, upper) if model_cap else configured
    return min(candidates)


@lru_cache(maxsize=1)
def get_local_tokenizer():
    """Load the local instruction tokenizer (used before the full model is on GPU)."""
    from transformers import AutoTokenizer

    source = _model_source()
    if not source:
        raise FileNotFoundError("No local LLM path or Hugging Face model id configured")
    local_only = Path(source).joinpath("config.json").exists()
    tokenizer = AutoTokenizer.from_pretrained(
        source,
        local_files_only=local_only,
        trust_remote_code=True,
        padding_side="left",
    )
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token_id = tokenizer.eos_token_id
    max_in = _resolve_max_input_tokens(tokenizer, source)
    tokenizer.model_max_length = max_in
    # Keep the end of the prompt (Question:) when truncating long RAG packs.
    tokenizer.truncation_side = "left"
    print(f"[llm] tokenizer model_max_length={max_in} truncation_side=left")
    return tokenizer


def get_local_model_and_tokenizer():
    """Return the shared local Qwen model + tokenizer (loads onto GPU if configured)."""
    return _load_local()


def is_llm_loaded() -> bool:
    return _load_local.cache_info().currsize > 0


def unload_llm() -> None:
    """Drop the local LLM from GPU so embedding/indexing can use VRAM."""
    _load_local.cache_clear()
    try:
        import gc

        import torch

        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:
        pass


def _generation_kwargs(max_tokens: int, *, temperature: float | None = None) -> dict:
    temp = config.TEMPERATURE if temperature is None else temperature
    kwargs: dict = {
        "max_new_tokens": max_tokens,
    }
    if temp and temp > 0:
        kwargs.update(do_sample=True, temperature=float(temp), top_p=0.85)
    else:
        kwargs["do_sample"] = False
    return kwargs


@lru_cache(maxsize=1)
def _load_local():
    import os

    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    source = _model_source()
    if not source:
        raise FileNotFoundError("No local LLM path or Hugging Face model id configured")
    local_only = Path(source).joinpath("config.json").exists()
    print(
        f"[llm] Loading {source} ({'local' if local_only else 'hub'}, "
        f"4-bit={config.LLM_LOAD_IN_4BIT}, temperature={config.TEMPERATURE})"
    )
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    tokenizer = get_local_tokenizer()
    kwargs: dict = {"low_cpu_mem_usage": True, "local_files_only": local_only, "trust_remote_code": True}
    if torch.cuda.is_available() and config.LLM_LOAD_IN_4BIT:
        kwargs["device_map"] = {"": 0}
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
        )
        kwargs["attn_implementation"] = "sdpa"
    elif torch.cuda.is_available():
        kwargs["device_map"] = {"": 0}
        kwargs["dtype"] = torch.bfloat16
        kwargs["attn_implementation"] = "sdpa"
    else:
        kwargs["device_map"] = "cpu"
        kwargs["torch_dtype"] = "auto"

    try:
        model = AutoModelForCausalLM.from_pretrained(source, **kwargs)
    except Exception as exc:
        from shared.embeddings import _shares_llm_weights

        if _shares_llm_weights():
            raise RuntimeError(
                f"Failed to load {source} for shared embed+LLM stack: {exc}"
            ) from exc
        fallback = "Qwen/Qwen2.5-7B-Instruct"
        if source.rstrip("/").endswith("Qwen2.5-14B-Instruct") and fallback not in source:
            print(f"[llm] 14B load failed ({exc}); falling back to {fallback} 4-bit")
            tokenizer = AutoTokenizer.from_pretrained(fallback, trust_remote_code=True)
            kwargs["local_files_only"] = False
            model = AutoModelForCausalLM.from_pretrained(fallback, **kwargs)
        else:
            raise
    model.eval()
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token_id = tokenizer.eos_token_id
    device = getattr(model, "device", None)
    if device is None:
        device = next(model.parameters()).device
    print(f"[llm] Model ready on {device}")
    return tokenizer, model


def _prepare_local_inputs(user_content: str):
    if len(user_content) > config.CONTEXT_MAX_CHARS:
        # Keep the tail so "Question:" / "Answer:" and contexts near the end survive.
        keep = config.CONTEXT_MAX_CHARS
        user_content = "[truncated]\n" + user_content[-keep:]

    tokenizer, model = _load_local()
    max_in = int(getattr(tokenizer, "model_max_length", 0) or config.LLM_MAX_INPUT_TOKENS)
    # OTel card uses a raw RAG completion prompt (no chat turns).
    if _is_otel_llm():
        formatted = user_content
        if not formatted.rstrip().endswith("Answer:"):
            formatted = formatted.rstrip() + "\n\nAnswer:"
        bos = getattr(tokenizer, "bos_token", None) or ""
        if bos and not formatted.startswith(bos):
            formatted = bos + formatted
    else:
        messages = [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": user_content},
        ]
        try:
            formatted = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        except Exception:
            formatted = tokenizer.apply_chat_template(
                [{"role": "user", "content": f"{_system_prompt()}\n\n{user_content}"}],
                tokenize=False,
                add_generation_prompt=True,
            )
    inputs = tokenizer(
        formatted,
        return_tensors="pt",
        truncation=True,
        max_length=max_in,
    )
    seq_len = int(inputs["input_ids"].shape[1])
    if seq_len >= max_in:
        print(f"[llm] prompt truncated to {max_in} tokens (was >= limit)")
    device = next(model.parameters()).device
    inputs = {k: v.to(device) for k, v in inputs.items()}
    return tokenizer, model, inputs


def _iter_local_tokens(user_content: str, *, max_tokens: int | None = None) -> Iterator[str]:
    """Stream decoded tokens from the local model; also fires the SSE callback."""
    try:
        import torch
        from transformers import TextIteratorStreamer

        tokenizer, model, inputs = _prepare_local_inputs(user_content)
        streamer = TextIteratorStreamer(
            tokenizer, skip_prompt=True, skip_special_tokens=True
        )
        gen_kwargs = _generation_kwargs(max_tokens or config.MAX_NEW_TOKENS)
        gen_kwargs["pad_token_id"] = tokenizer.pad_token_id
        gen_kwargs["streamer"] = streamer

        def _run() -> None:
            with torch.no_grad():
                model.generate(**inputs, **gen_kwargs)

        thread = threading.Thread(target=_run)
        thread.start()
        for piece in streamer:
            if piece:
                _emit_token(piece)
                yield piece
        thread.join()
    except Exception as exc:
        err = f"[LLM local error: {exc}]"
        _emit_token(err)
        yield err


def _answer_via_local(
    user_content: str, *, max_tokens: int | None = None, emit: bool = True
) -> str:
    try:
        import torch

        tokenizer, model, inputs = _prepare_local_inputs(user_content)
        prompt_len = inputs["input_ids"].shape[1]
        gen_kwargs = _generation_kwargs(max_tokens or config.MAX_NEW_TOKENS)
        gen_kwargs["pad_token_id"] = tokenizer.pad_token_id
        with torch.no_grad():
            out = model.generate(**inputs, **gen_kwargs)
        text = tokenizer.decode(out[0][prompt_len:], skip_special_tokens=True).strip()
        if emit:
            _emit_token(text)
        return text
    except Exception as exc:
        err = f"[LLM local error: {exc}]"
        if emit:
            _emit_token(err)
        return err


def _answer_stub(question: str, context: str) -> str:
    excerpt = (context or "")[:800]
    if len(context or "") > 800:
        excerpt += "..."
    return (
        "[LLM not configured — set LLM_MODEL_PATH or LLM_BASE_URL]\n"
        f"Question: {question}\n"
        f"Top context excerpt:\n{excerpt}"
    )


def preload_llm() -> None:
    """Load the local generator onto GPU at startup (not on first question)."""
    if config.LLM_USE_LOCAL and (config.LLM_MODEL_PATH or config.LLM_MODEL):
        _load_local()


def is_llm_available() -> bool:
    if config.LLM_BASE_URL:
        return True
    if not config.LLM_USE_LOCAL:
        return False
    if config.LLM_MODEL_PATH and Path(config.LLM_MODEL_PATH).joinpath("config.json").exists():
        return True
    return bool(config.LLM_MODEL)


def answer_question_raw(prompt: str, max_tokens: int = 100) -> str:
    """Lightweight LLM call for query analysis — short prompt, short output."""
    if config.LLM_BASE_URL:
        import requests

        url = f"{config.LLM_BASE_URL}/api/generate"
        payload = {
            "model": config.LLM_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": config.TEMPERATURE, "num_predict": max_tokens},
        }
        try:
            resp = requests.post(url, json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception:
            return ""
    if config.LLM_USE_LOCAL and config.LLM_MODEL_PATH:
        try:
            import torch

            tokenizer, model = _load_local()
            messages = [
                {"role": "system", "content": "Rewrite or classify only. Do not invent facts."},
                {"role": "user", "content": prompt},
            ]
            try:
                formatted = tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )
            except Exception:
                formatted = tokenizer.apply_chat_template(
                    [{"role": "user", "content": prompt}],
                    tokenize=False,
                    add_generation_prompt=True,
                )
            inputs = tokenizer(formatted, return_tensors="pt")
            device = next(model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}
            prompt_len = inputs["input_ids"].shape[1]
            gen_kwargs = _generation_kwargs(max_tokens, temperature=min(config.TEMPERATURE, 0.3))
            gen_kwargs["pad_token_id"] = tokenizer.pad_token_id
            with torch.no_grad():
                out = model.generate(**inputs, **gen_kwargs)
            return tokenizer.decode(out[0][prompt_len:], skip_special_tokens=True).strip()
        except Exception:
            return ""
    return ""
