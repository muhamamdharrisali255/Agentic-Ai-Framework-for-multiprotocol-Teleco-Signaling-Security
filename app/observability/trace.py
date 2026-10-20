"""Agent execution tracing (implementation_plan.md §35)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import config

LOG = logging.getLogger("agent.trace")
TRACE_DIR = config.PROJECT_ROOT / "data" / "traces"
TRACE_DIR.mkdir(parents=True, exist_ok=True)


def log_trace(payload: dict[str, Any]) -> None:
    LOG.info(json.dumps({k: payload[k] for k in payload if k != "evidence"}, default=str))
    path = TRACE_DIR / f"{payload.get('trace_id', 'unknown')}.json"
    try:
        path.write_text(json.dumps(payload, indent=2, default=str))
    except Exception:
        pass
