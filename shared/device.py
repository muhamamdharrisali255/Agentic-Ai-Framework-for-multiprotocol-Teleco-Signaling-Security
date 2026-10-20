"""GPU / device helpers for embeddings and status display."""

from __future__ import annotations


def resolve_device(preference: str = "auto") -> str:
    """Return a torch device string, preferring CUDA when available."""
    import torch

    pref = (preference or "auto").lower()
    if pref == "cpu":
        return "cpu"
    if torch.cuda.is_available() and pref in ("auto", "cuda", "gpu"):
        return "cuda"
    return "cpu"


def gpu_status() -> dict[str, str]:
    """Summarize accelerator availability for the UI."""
    import torch

    if not torch.cuda.is_available():
        return {
            "available": "false",
            "device": "cpu",
            "name": "none",
            "memory": "—",
        }

    idx = torch.cuda.current_device()
    props = torch.cuda.get_device_properties(idx)
    allocated = torch.cuda.memory_allocated(idx) / (1024**2)
    reserved = torch.cuda.memory_reserved(idx) / (1024**2)
    return {
        "available": "true",
        "device": f"cuda:{idx}",
        "name": props.name,
        "memory": f"{allocated:.0f} MiB used · {reserved:.0f} MiB reserved",
    }


def gpu_status_markdown() -> str:
    info = gpu_status()
    if info["available"] != "true":
        return "**GPU:** not available (running on CPU)"
    return f"**GPU:** `{info['name']}` · `{info['device']}` · {info['memory']}"
