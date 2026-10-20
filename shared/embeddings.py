"""Embedding utilities — Qwen2.5-Instruct (shared LLM) or dedicated Qwen3-Embedding."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import List

import numpy as np

import config
from shared.device import resolve_device

_DIM_CACHE: int | None = None
_QWEN_QUERY_TASK = (
    "Given a user question about telecom signaling security, "
    "retrieve relevant document passages that answer the query"
)


def _qwen_max_length() -> int:
    return int(getattr(config, "EMBEDDING_MAX_LENGTH", 2048) or 2048)


def _fix_otel_modules_json(model_path: Path) -> None:
    """HF OTel checkpoints list Dense layers that are not shipped; trim modules.json."""
    modules_file = model_path / "modules.json"
    if not modules_file.is_file():
        return
    if "otel" not in model_path.name.lower():
        return
    try:
        modules = json.loads(modules_file.read_text())
    except json.JSONDecodeError:
        return
    if not any("Dense" in str(m.get("type", "")) for m in modules):
        return
    fixed = [
        {
            "idx": 0,
            "name": "0",
            "path": "",
            "type": "sentence_transformers.models.Transformer",
        },
        {
            "idx": 1,
            "name": "1",
            "path": "1_Pooling",
            "type": "sentence_transformers.models.Pooling",
        },
        {
            "idx": 2,
            "name": "2",
            "path": "",
            "type": "sentence_transformers.models.Normalize",
        },
    ]
    backup = model_path / "modules.json.bak"
    if not backup.is_file():
        backup.write_text(modules_file.read_text())
    modules_file.write_text(json.dumps(fixed, indent=2) + "\n")


def _model_path(model_id: str) -> Path | None:
    p = Path(model_id)
    if p.joinpath("config.json").exists():
        return p
    return None


def _model_config(model_id: str) -> dict:
    p = _model_path(model_id)
    if not p:
        return {}
    try:
        return json.loads((p / "config.json").read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _is_qwen_dedicated_embedder(model_id: str) -> bool:
    mid = (model_id or "").lower()
    return "qwen" in mid and "embedding" in mid


def _is_otel_embedder(model_id: str) -> bool:
    mid = (model_id or "").lower()
    return "otel" in mid and "embedding" in mid


def _is_qwen_causal_embedder(model_id: str) -> bool:
    cfg = _model_config(model_id)
    arch = cfg.get("architectures") or []
    return any("CausalLM" in str(a) for a in arch)


def _shares_llm_weights() -> bool:
    """Share CausalLM weights only when embed+LLM are the same checkpoint on GPU.

    CPU-offloaded embedders (14B generator stack) always load a separate copy so
    the generator can own VRAM.
    """
    emb = str(config.EMBEDDING_MODEL or "").strip()
    llm = str(config.LLM_MODEL_PATH or config.LLM_MODEL or "").strip()
    if not emb or not llm:
        return False
    emb_device = str(getattr(config, "EMBEDDING_DEVICE", "cuda") or "cuda").lower()
    if emb_device.startswith("cpu"):
        return False

    def _norm(ref: str) -> str:
        p = Path(ref)
        if p.joinpath("config.json").exists():
            try:
                return str(p.resolve())
            except OSError:
                return str(p)
        return ref.rstrip("/").lower()

    return _norm(emb) == _norm(llm)


def _is_qwen_instruct_as_embedder(model_id: str) -> bool:
    """Causal Qwen instruct/chatbot checkpoints used as last-token embedders."""
    mid = (model_id or "").lower()
    if "otel" in mid and "embedding" in mid:
        return False
    if "qwen" not in mid and "telecom-chatbot" not in mid:
        return False
    if "embedding" in mid:
        return False
    return any(k in mid for k in ("instruct", "chatbot", "telecom-chatbot", "qwen2.5"))


def _last_token_pool(last_hidden_states, attention_mask):
    import torch

    left_padding = attention_mask[:, -1].sum() == attention_mask.shape[0]
    if left_padding:
        return last_hidden_states[:, -1]
    sequence_lengths = attention_mask.sum(dim=1) - 1
    batch_size = last_hidden_states.shape[0]
    return last_hidden_states[
        torch.arange(batch_size, device=last_hidden_states.device),
        sequence_lengths,
    ]


class _QwenNativeEmbedder:
    """Qwen embeddings via native AutoTokenizer + last-token pooling."""

    def __init__(self, *, shared_llm: bool) -> None:
        self._shared_llm = shared_llm
        self._tokenizer = None
        self._model = None
        self._device = "cpu"

    def _model_id(self) -> str:
        if self._shared_llm:
            from shared.llm import llm_model_source

            return llm_model_source()
        return config.EMBEDDING_MODEL

    def _ensure_tokenizer(self) -> None:
        if self._tokenizer is not None:
            return
        if self._shared_llm:
            from shared.llm import get_local_tokenizer

            self._tokenizer = get_local_tokenizer()
            print("[embeddings] Qwen tokenizer ready (shared with LLM)")
            return
        from transformers import AutoTokenizer

        model_id = self._model_id()
        local = _model_path(model_id) is not None
        load_kwargs = {"trust_remote_code": True, "local_files_only": local}
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_id,
            padding_side="left",
            **load_kwargs,
        )
        if self._tokenizer.pad_token_id is None:
            self._tokenizer.pad_token_id = self._tokenizer.eos_token_id
        print(f"[embeddings] Qwen tokenizer ready ({model_id})")

    def _ensure_model(self) -> None:
        if self._model is not None:
            return
        self._ensure_tokenizer()
        if self._shared_llm:
            from shared.llm import get_local_model_and_tokenizer

            self._tokenizer, self._model = get_local_model_and_tokenizer()
            self._device = str(next(self._model.parameters()).device)
            print(f"[embeddings] Using shared Qwen LLM weights on {self._device}")
            return

        import torch
        from transformers import AutoModel, AutoModelForCausalLM

        model_id = self._model_id()
        device = resolve_device(config.EMBEDDING_DEVICE)
        local = _model_path(model_id) is not None
        load_kwargs = {"trust_remote_code": True, "local_files_only": local}
        cfg = _model_config(model_id)
        is_causal = _is_qwen_causal_embedder(model_id)
        loader = AutoModelForCausalLM if is_causal else AutoModel
        print(f"[embeddings] Loading Qwen model {model_id} on {device}")
        try:
            self._model = loader.from_pretrained(model_id, **load_kwargs).to(device)
            self._device = device
        except Exception as exc:
            if device == "cpu":
                raise
            print(f"[embeddings] Qwen model failed on {device} ({exc}); retrying on cpu")
            self._model = loader.from_pretrained(model_id, **load_kwargs).to("cpu")
            self._device = "cpu"
        self._model.eval()

    def _format_query(self, query: str) -> str:
        return f"Instruct: {_QWEN_QUERY_TASK}\nQuery:{query}"

    def _forward_hidden(self, batch_dict: dict):
        import torch

        with torch.no_grad():
            # Prefer the transformer backbone — avoid CausalLM lm_head (huge logits / OOM).
            base = getattr(self._model, "model", None)
            if base is not None and callable(base):
                outputs = base(**batch_dict)
                return outputs.last_hidden_state
            outputs = self._model(**batch_dict, output_hidden_states=True)
            if getattr(outputs, "hidden_states", None):
                return outputs.hidden_states[-1]
            return outputs.last_hidden_state

    def encode(
        self,
        texts: List[str],
        *,
        batch_size: int,
        is_query: bool = False,
    ) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dimension), dtype=np.float32)
        import torch
        import torch.nn.functional as F

        self._ensure_model()
        inputs = [self._format_query(t) if is_query else t for t in texts]
        out: list[np.ndarray] = []
        for i in range(0, len(inputs), batch_size):
            batch = inputs[i : i + batch_size]
            batch_dict = self._tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=_qwen_max_length(),
                return_tensors="pt",
            )
            batch_dict = {k: v.to(self._device) for k, v in batch_dict.items()}
            hidden = self._forward_hidden(batch_dict)
            # Instruct/chatbot checkpoints are not trained as embedders. Masked mean
            # pooling retrieves far better than last-token pooling on this stack.
            mask = batch_dict["attention_mask"].unsqueeze(-1).to(hidden.dtype)
            summed = (hidden * mask).sum(dim=1)
            denom = mask.sum(dim=1).clamp(min=1e-6)
            embeddings = F.normalize(summed / denom, p=2, dim=1)
            out.append(embeddings.float().cpu().numpy())
            if self._device != "cpu":
                try:
                    import torch

                    torch.cuda.empty_cache()
                except Exception:
                    pass
        return np.vstack(out).astype(np.float32)

    @property
    def dimension(self) -> int:
        cfg = _model_config(self._model_id())
        if cfg.get("hidden_size"):
            return int(cfg["hidden_size"])
        self._ensure_model()
        return int(self._model.config.hidden_size)


_QWEN_NATIVE: _QwenNativeEmbedder | None = None


def _qwen_native() -> _QwenNativeEmbedder:
    global _QWEN_NATIVE
    if _QWEN_NATIVE is None:
        _QWEN_NATIVE = _QwenNativeEmbedder(shared_llm=_shares_llm_weights())
    return _QWEN_NATIVE


def _uses_qwen_native() -> bool:
    model_id = config.EMBEDDING_MODEL
    # OTel / SentenceTransformer embedders must not go through Qwen CausalLM pooling.
    if _is_otel_embedder(model_id):
        return False
    return (
        _is_qwen_dedicated_embedder(model_id)
        or _is_qwen_causal_embedder(model_id)
        or _is_qwen_instruct_as_embedder(model_id)
        or _shares_llm_weights()
    )


@lru_cache(maxsize=1)
def get_embedding_model():
    if _uses_qwen_native():
        return _qwen_native()
    device = resolve_device(config.EMBEDDING_DEVICE)
    model_id = config.EMBEDDING_MODEL
    local_path = _model_path(model_id)
    if local_path is not None:
        _fix_otel_modules_json(local_path)
    print(f"[embeddings] Loading {model_id} on {device}")
    local = local_path is not None
    from sentence_transformers import SentenceTransformer

    kwargs: dict = {
        "device": device,
        "trust_remote_code": True,
        "local_files_only": local,
    }
    try:
        return SentenceTransformer(model_id, **kwargs)
    except Exception as exc:
        if device != "cpu":
            print(f"[embeddings] {model_id} failed on {device} ({exc}); retrying on cpu")
            kwargs["device"] = "cpu"
            return SentenceTransformer(model_id, **kwargs)
        raise


def _encode_st(
    texts: List[str],
    *,
    batch_size: int | None,
    prompt_name: str | None,
) -> np.ndarray:
    model = get_embedding_model()
    bs = batch_size or config.EMBEDDING_BATCH_SIZE
    kwargs: dict = {
        "batch_size": bs,
        "show_progress_bar": len(texts) > 50,
        "normalize_embeddings": True,
        "convert_to_numpy": True,
    }
    if prompt_name and hasattr(model, "prompts") and prompt_name in getattr(model, "prompts", {}):
        kwargs["prompt_name"] = prompt_name
    embeddings = model.encode(texts, **kwargs)
    return np.asarray(embeddings, dtype=np.float32)


def embedding_dimension() -> int:
    global _DIM_CACHE
    if _DIM_CACHE is not None:
        return _DIM_CACHE
    if _uses_qwen_native():
        _DIM_CACHE = _qwen_native().dimension
    else:
        model = get_embedding_model()
        if hasattr(model, "get_embedding_dimension"):
            _DIM_CACHE = int(model.get_embedding_dimension())
        elif hasattr(model, "get_sentence_embedding_dimension"):
            _DIM_CACHE = int(model.get_sentence_embedding_dimension())
        else:
            _DIM_CACHE = int(_encode_st(["probe"], batch_size=1, prompt_name=None).shape[1])
    return _DIM_CACHE


def embed_texts(texts: List[str], batch_size: int | None = None) -> np.ndarray:
    """Embed document/chunk texts."""
    bs = batch_size or config.EMBEDDING_BATCH_SIZE
    if _uses_qwen_native():
        return _qwen_native().encode(texts, batch_size=bs, is_query=False)
    return _encode_st(texts, batch_size=bs, prompt_name="Retrieval-document")


def embed_query(query: str) -> np.ndarray:
    if _uses_qwen_native():
        return _qwen_native().encode([query], batch_size=1, is_query=True)[0]
    return _encode_st([query], batch_size=1, prompt_name="Retrieval-query")[0]
