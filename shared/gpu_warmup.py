"""Preload GPU models at startup for maximum CUDA utilization."""

from __future__ import annotations

import os

import config


def _configure_cuda() -> None:
    os.environ.setdefault("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
    os.environ.setdefault("CUDA_MPS_ACTIVE_THREAD_PERCENTAGE", "100")
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.set_device(0)
            torch.backends.cudnn.benchmark = True
            torch.set_float32_matmul_precision("high")
    except Exception:
        pass


def preload_gpu() -> None:
    """Load the local LLM, embeddings, and Docling OCR models onto GPU before serving."""
    _configure_cuda()

    import torch
    from shared.device import gpu_status_markdown
    from shared.embeddings import embed_texts, get_embedding_model

    if not torch.cuda.is_available():
        print("[gpu] CUDA not available — skipping preload")
        return

    print("[gpu] Preloading models onto CUDA…")

    from shared.llm import get_local_tokenizer, is_llm_available, preload_llm

    if is_llm_available():
        get_local_tokenizer()
        print("[gpu] LLM tokenizer loaded")
        if config.LLM_PRELOAD:
            try:
                preload_llm()
                print(f"[gpu] LLM loaded: {config.LLM_MODEL_PATH or config.LLM_MODEL}")
            except Exception as exc:
                print(f"[gpu] LLM preload failed: {exc} — will load on first query")

    get_embedding_model()
    batch = max(1, min(config.EMBEDDING_BATCH_SIZE, 4))
    embed_texts(["gpu warmup"] * batch, batch_size=batch)
    print(f"[gpu] Embeddings warmed: {config.EMBEDDING_MODEL} (batch_size={batch})")

    if config.DOCLING_PRELOAD:
        try:
            from shared.docling_gpu import get_docling_converter

            get_docling_converter()
            print("[gpu] Docling CUDA converter preloaded (layout + RapidOCR torch)")
        except Exception as exc:
            print(f"[gpu] Docling preload skipped: {exc}")

    print(f"[gpu] Ready — {gpu_status_markdown()}")
