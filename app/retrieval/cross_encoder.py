"""Cross-encoder reranking — Qwen3-Reranker, OTel, or ms-marco fallback.

When the generator holds GPU VRAM, the reranker falls back to CPU automatically
so Case 2 retrieval still gets CE ranking (no silent skip).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_encoder = None
_encoder_name = ""
_encoder_device = ""
_otel_model = None
_otel_tokenizer = None
_otel_device = ""


def _is_otel_reranker(model_name: str) -> bool:
    low = model_name.lower()
    return "otel" in low and "reranker" in low


def _is_qwen3_reranker(model_name: str) -> bool:
    low = model_name.lower()
    return "qwen3" in low and "rerank" in low


def _cuda_free_mb() -> float:
    try:
        import torch

        if not torch.cuda.is_available():
            return 0.0
        free, _total = torch.cuda.mem_get_info()
        return float(free) / (1024.0 * 1024.0)
    except Exception:
        return 0.0


def _configured_device_pref() -> str:
    try:
        from app.config.settings import settings

        return str(getattr(settings, "cross_encoder_device", "auto") or "auto").lower()
    except Exception:
        return "auto"


def _min_free_mb() -> float:
    try:
        from app.config.settings import settings

        return float(getattr(settings, "cross_encoder_min_free_mb", 1200) or 1200)
    except Exception:
        return 1200.0


def _reranker_device() -> str:
    """Prefer CUDA only when enough free VRAM; else CPU (LLM often owns the GPU)."""
    pref = _configured_device_pref()
    if pref in {"cpu", "cuda"}:
        if pref == "cuda":
            import torch

            return "cuda" if torch.cuda.is_available() else "cpu"
        return "cpu"
    import torch

    if not torch.cuda.is_available():
        return "cpu"
    free = _cuda_free_mb()
    if free < _min_free_mb():
        print(f"[reranker] CUDA free {free:.0f}MB < {_min_free_mb():.0f}MB — using CPU")
        return "cpu"
    return "cuda"


def _reset_encoders() -> None:
    global _encoder, _encoder_name, _encoder_device
    global _otel_model, _otel_tokenizer, _otel_device
    _encoder = None
    _encoder_name = ""
    _encoder_device = ""
    _otel_model = None
    _otel_tokenizer = None
    _otel_device = ""


def _is_oom(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return (
        "out of memory" in msg
        or "cuda out of memory" in msg
        or "cudnn_status_alloc_failed" in msg
        or type(exc).__name__ in {"OutOfMemoryError", "CUDAOutOfMemoryError"}
    )


def _get_ms_marco_encoder(device: str | None = None):
    from sentence_transformers import CrossEncoder

    device = device or _reranker_device()
    return CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2", device=device)


def _get_cross_encoder(model_name: str, *, force_device: str | None = None):
    global _encoder, _encoder_name, _encoder_device
    device = force_device or _reranker_device()
    if (
        _encoder is not None
        and _encoder_name == model_name
        and _encoder_device == device
    ):
        return _encoder
    from sentence_transformers import CrossEncoder

    local = Path(model_name).joinpath("config.json").exists()
    try:
        kwargs: dict[str, Any] = {
            "trust_remote_code": True,
            "local_files_only": local,
            "device": device,
        }
        if _is_qwen3_reranker(model_name):
            # Official Qwen3-Reranker prompt path (sentence-transformers ≥ 3.x).
            kwargs["prompts"] = {
                "classification": (
                    "Given a user query and a document passage, classify whether "
                    "the passage is relevant for answering the query"
                ),
            }
            kwargs["default_prompt_name"] = "classification"
        _encoder = CrossEncoder(model_name, **kwargs)
        print(f"[reranker] Loaded {model_name} on {device}")
    except Exception as exc:
        if _is_oom(exc) and device == "cuda":
            print(f"[reranker] {model_name} CUDA OOM on load; retrying on CPU")
            try:
                import torch

                torch.cuda.empty_cache()
            except Exception:
                pass
            return _get_cross_encoder(model_name, force_device="cpu")
        print(f"[reranker] {model_name} failed ({exc}); using ms-marco fallback")
        _encoder = _get_ms_marco_encoder(device="cpu" if device == "cuda" and _is_oom(exc) else device)
        device = "cpu" if _is_oom(exc) else device
    _encoder_name = model_name
    _encoder_device = device
    return _encoder


def _get_otel_reranker(model_name: str, *, force_device: str | None = None):
    global _otel_model, _otel_tokenizer, _otel_device, _encoder_name
    device = force_device or _reranker_device()
    if (
        _otel_model is not None
        and _encoder_name == model_name
        and _otel_device == device
    ):
        return _otel_model, _otel_tokenizer, _otel_device

    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    local = Path(model_name).joinpath("config.json").exists()
    kwargs = {"trust_remote_code": True}
    if local:
        kwargs["local_files_only"] = True
    try:
        _otel_tokenizer = AutoTokenizer.from_pretrained(model_name, **kwargs)
        _otel_model = AutoModelForSequenceClassification.from_pretrained(model_name, **kwargs)
        _otel_model.eval()
        _otel_model.to(device)
    except Exception as exc:
        if _is_oom(exc) and device == "cuda":
            print(f"[reranker] OTel CUDA OOM on load; retrying on CPU")
            try:
                torch.cuda.empty_cache()
            except Exception:
                pass
            return _get_otel_reranker(model_name, force_device="cpu")
        raise
    _otel_device = device
    _encoder_name = model_name
    return _otel_model, _otel_tokenizer, _otel_device


def _otel_predict(pairs: list[tuple[str, str]], model_name: str) -> list[float]:
    import torch

    model, tokenizer, device = _get_otel_reranker(model_name)
    inputs = tokenizer(
        [list(p) for p in pairs],
        padding=True,
        truncation=True,
        max_length=512,
        return_tensors="pt",
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}
    try:
        with torch.no_grad():
            logits = model(**inputs).logits.squeeze(-1)
    except Exception as exc:
        if _is_oom(exc) and device == "cuda":
            print("[reranker] OTel CUDA OOM on predict; moving to CPU")
            try:
                torch.cuda.empty_cache()
            except Exception:
                pass
            _reset_encoders()
            model, tokenizer, device = _get_otel_reranker(model_name, force_device="cpu")
            inputs = tokenizer(
                [list(p) for p in pairs],
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt",
            )
            inputs = {k: v.to(device) for k, v in inputs.items()}
            with torch.no_grad():
                logits = model(**inputs).logits.squeeze(-1)
        else:
            raise
    if logits.ndim == 0:
        return [float(logits.cpu())]
    return [float(x) for x in logits.cpu().tolist()]


def _predict_pairs(encoder, pairs: list[tuple[str, str]], model_name: str) -> list[float]:
    import torch

    try:
        return [float(s) for s in encoder.predict(pairs)]
    except Exception as exc:
        if _is_oom(exc) and _encoder_device == "cuda":
            print("[reranker] CUDA OOM on predict; reloading on CPU")
            try:
                torch.cuda.empty_cache()
            except Exception:
                pass
            _reset_encoders()
            encoder = _get_cross_encoder(model_name, force_device="cpu")
            return [float(s) for s in encoder.predict(pairs)]
        raise


def rerank_with_cross_encoder(
    query: str,
    items: list[dict[str, Any]],
    *,
    model_name: str,
    top_k: int,
    score_margin: float | None = None,
) -> list[dict[str, Any]]:
    """Score query–passage pairs with a cross-encoder; return top_k by CE score.

    When score_margin is set, drop passages farther than that from the best CE
    score so the generator is not fed adjacent-but-weaker topics. Generic —
    no document/category hardfixes.
    """
    if not items or top_k <= 0:
        return []
    if len(items) == 1:
        return items[:1]

    if score_margin is None:
        try:
            from app.config.settings import settings

            score_margin = float(settings.cross_encoder_score_margin)
        except Exception:
            score_margin = 2.0

    # Cap CE pool on CPU — scoring hundreds of pairs with Qwen3-Reranker is slow.
    pool = items
    device = _reranker_device()
    if device == "cpu" and len(pool) > 80:
        pool = pool[:80]

    pairs: list[tuple[str, str]] = []
    for ev in pool:
        body = str(ev.get("body") or ev.get("text") or "")
        section = str(ev.get("section") or "")
        passage = f"{section}\n{body}".strip()[:1800]
        pairs.append((query, passage))

    if _is_otel_reranker(model_name):
        scores = _otel_predict(pairs, model_name)
    else:
        encoder = _get_cross_encoder(model_name)
        scores = _predict_pairs(encoder, pairs, model_name)

    scored = list(zip(pool, scores))
    scored.sort(key=lambda x: x[1], reverse=True)

    best = float(scored[0][1])
    margin = max(0.0, float(score_margin))
    kept = [(ev, ce) for ev, ce in scored if best - float(ce) <= margin]
    if not kept:
        kept = scored[:1]
    # Always retain at least the top hit; cap at top_k after the gap filter.
    kept = kept[:top_k]

    out: list[dict[str, Any]] = []
    for ev, ce_score in kept:
        row = dict(ev)
        row["score"] = ce_score
        row["_cross_encoder_score"] = ce_score
        out.append(row)
    return out
